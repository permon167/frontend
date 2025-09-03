// src/App.js
import React, { useEffect, useMemo, useState } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  useLocation,
} from "react-router-dom";

/** ========= Config ========= */
const HOLDER_API =
  process.env.REACT_APP_HOLDER_API || "http://localhost:8001";
const VERIFIER_API =
  process.env.REACT_APP_VERIFIER_API ||
  "https://TU-DOMINIO-FIJO.ngrok-free.app";

const BYPASS = "ngrok-skip-browser-warning=true";
const withBypass = (url) => {
  const sep = url.includes("?") ? "&" : "?";
  return `${url}${sep}${BYPASS}`;
};

async function fetchBypass(url, init = {}) {
  return fetch(withBypass(url), init);
}
async function getJSON(url) {
  const r = await fetchBypass(url);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}
async function postJSON(url, body) {
  const r = await fetchBypass(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`HTTP ${r.status}: ${t || r.statusText}`);
  }
  return r.json();
}
const pretty = (x) => {
  try {
    return JSON.stringify(x, null, 2);
  } catch {
    return String(x);
  }
};
const rndState = (p = "STATE") =>
  `${p}_${Math.random().toString(36).slice(2)}_${Date.now()}`;

/** ========= Vista de /verification-result ========= */
function VerificationResult() {
  const [data, setData] = useState(null);
  const location = useLocation();
  const qs = useMemo(() => {
    const u = new URLSearchParams(location.search);
    return Object.fromEntries(u.entries());
  }, [location.search]);

  useEffect(() => {
    (async () => {
      try {
        const json = await getJSON(`${VERIFIER_API}/verifier/last-result`);
        setData(json);
      } catch (e) {
        setData({ error: String(e) });
      }
    })();
  }, []);

  return (
    <div className="container">
      <h2>Resultado de verificación</h2>
      <p><b>Parámetros de URL</b></p>
      <pre>{pretty(qs)}</pre>
      <p><b>/verifier/last-result</b> (Verifier público)</p>
      <pre>{pretty(data)}</pre>
      <Link to="/">⬅️ Volver</Link>
    </div>
  );
}

/** ========= Tarjeta de credencial ========= */
function CredentialCard({
  index,
  cred,
  decoded,
  onDecode,
  onDelete,
  onVerifyEBSI,
  onAutoPresent,
}) {
  const { header, payload } = cred || {};
  const exp =
    payload?.exp || payload?.expirationDate || payload?.vc?.expirationDate;

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-header">
        <strong>Credencial #{index}</strong>
      </div>
      <div className="card-body">
        <div>
          <div><b>typ</b>: {header?.typ}</div>
          <div><b>alg</b>: {header?.alg}</div>
          <div><b>exp</b>: {String(exp)}</div>
        </div>

        <div style={{ marginTop: 8 }}>
          <button onClick={() => onDecode(index)}>🔎 Ver detalle</button>{" "}
          <button onClick={() => onDelete(index)}>🗑️ Eliminar</button>{" "}
          <button onClick={onVerifyEBSI}>✅ OIDC4VP</button>{" "}
          <button onClick={() => onAutoPresent(index)}>
            📤 Presentar (Auto OID4VP)
          </button>
        </div>

        {decoded && (
          <>
            <p style={{ marginTop: 8 }}><b>Detalle decodificado</b></p>
            <pre>{pretty(decoded)}</pre>
          </>
        )}
      </div>
    </div>
  );
}

/** ========= Pantalla principal (Holder) ========= */
function WalletApp() {
  const [holderDid, setHolderDid] = useState(
    localStorage.getItem("holder_did") || ""
  );
  const [offerUrl, setOfferUrl] = useState("");
  const [creds, setCreds] = useState([]);
  const [decodedByIndex, setDecodedByIndex] = useState({});
  const [openidUrl, setOpenidUrl] = useState(""); // QR / openid:// del Verifier
  const [autoPresentResult, setAutoPresentResult] = useState(null);
  const [verifierLast, setVerifierLast] = useState(null);
  const [busy, setBusy] = useState(false);

  // 👉 Al cargar, si no hay DID, lo creamos/obtenemos automáticamente del backend
  useEffect(() => {
    (async () => {
      try {
        if (holderDid && holderDid.startsWith("did:jwk:")) return;
        const res = await postJSON(`${HOLDER_API}/holder/create-did-jwk`, {}); // idempotente en tu backend
        const did = res?.did || res?.holder_did || res?.did_jwk || "";
        if (did) {
          setHolderDid(did);
          localStorage.setItem("holder_did", did);
        }
      } catch {
        // si falla, dejamos que el usuario lo pegue manual si quiere
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const refreshCreds = async () => {
    setBusy(true);
    try {
      // ❌ Sin password en UI — usamos "default" siempre
      const json = await postJSON(`${HOLDER_API}/holder/credentials`, {
        password: "default",
      });
      const arr = (json?.credentials || json || []).map((raw) => {
        try {
          const [h, p] = String(raw).split(".");
          const decode = (s) =>
            JSON.parse(atob(s.replace(/-/g, "+").replace(/_/g, "/")));
          return { raw, header: decode(h), payload: decode(p) };
        } catch {
          return { raw, header: {}, payload: {} };
        }
      });
      setCreds(arr);
    } finally {
      setBusy(false);
    }
  };

  const receiveOffer = async () => {
    setBusy(true);
    try {
      const did = holderDid;
      if (!did?.startsWith("did:jwk:")) {
        throw new Error("No se pudo obtener el DID del holder.");
      }
      // ❌ Sin password en UI — usamos "default" siempre
      await postJSON(`${HOLDER_API}/holder/receive-oid4vc`, {
        credential_offer_uri: offerUrl,
        holder_did: did,
        password: "default",
      });
      await refreshCreds();
      alert("✅ Credencial recibida.");
    } catch (e) {
      alert("❌ " + e.message);
    } finally {
      setBusy(false);
    }
  };

  const decodeCredential = async (index) => {
    try {
      const target = creds[index]?.raw;
      if (!target) return;
      const result = await postJSON(`${HOLDER_API}/holder/decode-credential`, {
        jwt: target,
      });
      setDecodedByIndex((m) => ({ ...m, [index]: result }));
    } catch (e) {
      alert("❌ " + e.message);
    }
  };

  const deleteCredential = async (index) => {
    if (!window.confirm(`¿Eliminar credencial #${index}?`)) return;
    try {
      await postJSON(`${HOLDER_API}/holder/delete-credential`, {
        password: "default",
        index,
      });
      await refreshCreds();
    } catch (e) {
      alert("❌ " + e.message);
    }
  };

  // Pide openid:// al Verifier (para QR / wallets externas)
  const handleVerifyWithEBSI = async () => {
    setBusy(true);
    try {
      const state = rndState("EBSI");
      const u = new URL(`${VERIFIER_API}/authorize/openid`);
      u.searchParams.set("flow", "vp");
      u.searchParams.set("format", "json");
      u.searchParams.set("response_type", "vp_token id_token"); // o solo "vp_token"
      u.searchParams.set("client_id", "dummy-client");
      u.searchParams.set("redirect_uri", "openid://"); // estilo hub/wallet
      u.searchParams.set("scope", "openid");
      u.searchParams.set("state", state);
      u.searchParams.set("response_mode", "direct_post");

      const j = await getJSON(u.toString());
      const openid = j.openid_url ?? j.openid;
      setOpenidUrl(openid || "");

      try {
        const last = await getJSON(`${VERIFIER_API}/verifier/last-result`);
        setVerifierLast(last);
      } catch { /* noop */ }
    } catch (e) {
      alert("❌ " + e.message);
    } finally {
      setBusy(false);
    }
  };

  // Auto-presentación: el Holder envía VP al Verifier (sin pedir password)
  const handleAutoPresent = async (index) => {
    setBusy(true);
    try {
      const did = holderDid;
      if (!did?.startsWith("did:jwk:")) {
        throw new Error("No se pudo obtener el DID del holder.");
      }
      const state = rndState("PRESENT");

      const body = {
        holder_did: did,
        password: "default",        // 👈 sin password en UI
        select: [index],
        send: true,
        auth: {
          redirect_uri: `${VERIFIER_API}/verifier/response`,
          state,
        },
      };
      const data = await postJSON(`${HOLDER_API}/wallet/present`, body);
      setAutoPresentResult(data);

      try {
        const last = await getJSON(`${VERIFIER_API}/verifier/last-result`);
        setVerifierLast(last);
      } catch { /* noop */ }

      if (data.sent && (data.post_status === 200 || data.post_status === 302)) {
        alert("✅ Presentación enviada al Verifier.");
      } else {
        alert("⚠️ Presentación generada pero no enviada (revisa logs / post_status).");
      }
    } catch (e) {
      alert("❌ " + e.message);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    refreshCreds();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="container" style={{ maxWidth: 960, margin: "0 auto" }}>
      <header style={{ display: "flex", justifyContent: "space-between" }}>
        <h1>Wallet SSI (Holder)</h1>
        <nav>
          <Link to="/verification-result">Ver /verifier/last-result</Link>
        </nav>
      </header>

      <section className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><strong>Configuración</strong></div>
        <div className="card-body" style={{ display: "grid", gap: 8 }}>
          <label>
            Holder DID (did:jwk):
            <input
              style={{ width: "100%" }}
              value={holderDid}
              onChange={(e) => {
                setHolderDid(e.target.value);
                localStorage.setItem("holder_did", e.target.value);
              }}
              placeholder="did:jwk:..."
              readOnly={!holderDid} // aparece ya rellenado; si falla creación se podrá editar
            />
          </label>
          <div style={{ fontSize: 12, opacity: 0.8 }}>
            <div><b>Holder API:</b> {HOLDER_API}</div>
            <div><b>Verifier API:</b> {VERIFIER_API}</div>
          </div>
          <div>
            <button onClick={refreshCreds} disabled={busy}>🔄 Refrescar credenciales</button>
          </div>
        </div>
      </section>

        <section className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><strong>Recibir credencial (OID4VCI)</strong></div>
        <div className="card-body">
          <label>
            URL/QR (credential_offer_uri):
            <input
              style={{ width: "100%" }}
              value={offerUrl}
              onChange={(e) => setOfferUrl(e.target.value)}
              placeholder="openid-credential-offer://?credential_offer=..."
            />
          </label>
          <div style={{ marginTop: 8 }}>
            <button onClick={receiveOffer} disabled={busy || !offerUrl}>
              🎫 Recibir credencial externa
            </button>
          </div>
        </div>
      </section>

      <section className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><strong>Credenciales en la wallet</strong></div>
        <div className="card-body">
          {creds.length === 0 && <p>No hay credenciales almacenadas.</p>}
          {creds.map((c, i) => (
            <CredentialCard
              key={i}
              index={i}
              cred={c}
              decoded={decodedByIndex[i]}
              onDecode={decodeCredential}
              onDelete={deleteCredential}
              onVerifyEBSI={handleVerifyWithEBSI}
              onAutoPresent={handleAutoPresent}
            />
          ))}
        </div>
      </section>

      <section className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><strong>Debug</strong></div>
        <div className="card-body">
          <p><b>openid:// (del Verifier)</b></p>
          <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {openidUrl || "—"}
          </pre>

          <p><b>Auto-presentación (/wallet/present en Holder)</b></p>
          <pre>{pretty(autoPresentResult || {})}</pre>

          <p><b>Último resultado del Verifier (/verifier/last-result)</b></p>
          <pre>{pretty(verifierLast || {})}</pre>
        </div>
      </section>
    </div>
  );
}

/** ========= App con rutas ========= */
export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<WalletApp />} />
        <Route path="/verification-result" element={<VerificationResult />} />
      </Routes>
    </Router>
  );
}

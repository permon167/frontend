// src/App.js
import React, { useEffect, useMemo, useState } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  useLocation,
  useNavigate,
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

/** ====== helpers JWT ====== */
function b64urlDecode(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  return atob(s);
}
function decodeJwtParts(jwt) {
  const [h, p] = String(jwt).split(".");
  if (!h || !p) return { header: {}, payload: {} };
  try {
    const header = JSON.parse(b64urlDecode(h));
    const payload = JSON.parse(b64urlDecode(p));
    return { header, payload };
  } catch {
    return { header: {}, payload: {} };
  }
}

/** ========= Vista de /verification-result (lee del Verifier) ========= */
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
      <h2>Resultado de verificación (Verifier)</h2>
      <p><b>Parámetros de URL</b></p>
      <pre>{pretty(qs)}</pre>
      <p><b>/verifier/last-result</b></p>
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

  const subj =
    payload?.vc?.credentialSubject ||
    payload?.credentialSubject ||
    {};

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-header">
        <strong>Credencial #{index}</strong>
      </div>
      <div className="card-body">
        <div>
          <div><b>typ</b>: {header?.typ}</div>
          <div><b>alg</b>: {header?.alg}</div>
          {exp && <div><b>exp</b>: {String(exp)}</div>}
          {Object.keys(subj).length > 0 && (
            <div style={{ marginTop: 6 }}>
              <b>Sujeto (preview)</b>
              <pre>{pretty(subj)}</pre>
            </div>
          )}
        </div>

        <div style={{ marginTop: 8 }}>
          <button onClick={() => onDecode(index)}>🔎 Ver detalle</button>{" "}
          <button onClick={() => onDelete(index)}>🗑️ Eliminar</button>{" "}
          <button onClick={onVerifyEBSI}>✅ OIDC4VP (QR Verifier)</button>{" "}
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
  const navigate = useNavigate();

  const [holderDid, setHolderDid] = useState(
    localStorage.getItem("holder_did") || ""
  );
  const [offerUrl, setOfferUrl] = useState("");
  const [creds, setCreds] = useState([]); // [{ jwt, header, payload }]
  const [decodedByIndex, setDecodedByIndex] = useState({});
  const [openidUrl, setOpenidUrl] = useState("");
  const [autoPresentResult, setAutoPresentResult] = useState(null);
  const [verifierLast, setVerifierLast] = useState(null);
  const [busy, setBusy] = useState(false);

  // Auto-crear/obtener DID al cargar si no existe
  useEffect(() => {
    (async () => {
      try {
        if (holderDid && holderDid.startsWith("did:jwk:")) return;
        const res = await postJSON(`${HOLDER_API}/holder/create-did-jwk`, {});
        const did = res?.did || res?.holder_did || res?.did_jwk || "";
        if (did) {
          setHolderDid(did);
          localStorage.setItem("holder_did", did);
        }
      } catch {
        // si falla, el usuario podrá pegarlo manualmente
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Lista credenciales SOLO cuando ya hay DID
  useEffect(() => {
    if (holderDid && holderDid.startsWith("did:jwk:")) {
      refreshCreds();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [holderDid]);

  const normalizeCredentialItem = (item) => {
    const jwt =
      (typeof item === "string" && item) ||
      item?.jwt ||
      item?.credential ||
      item?.raw ||
      "";

    const { header, payload } = decodeJwtParts(jwt);
    return { jwt, header, payload };
  };

  const refreshCreds = async () => {
    setBusy(true);
    try {
      const json = await postJSON(`${HOLDER_API}/holder/credentials`, {
        holder_did: holderDid,
        password: "default",
      });
      const list = Array.isArray(json?.credentials) ? json.credentials : json;
      const arr = (Array.isArray(list) ? list : []).map(normalizeCredentialItem);
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
      const target = creds[index]?.jwt;
      if (!target) return;
      const result = await postJSON(`${HOLDER_API}/holder/decode-credential`, {
        holder_did: holderDid,         // 👈 añadido
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
        holder_did: holderDid,
        password: "default",
        index,
      });
      await refreshCreds();
    } catch (e) {
      alert("❌ " + e.message);
    }
  };

  // OIDC4VP (QR): pedir openid:// al Verifier (necesita CORS en Verifier)
  const handleVerifyWithEBSI = async () => {
    setBusy(true);
    try {
      const state = rndState("EBSI");
      const u = new URL(`${VERIFIER_API}/authorize/openid`);
      u.searchParams.set("flow", "vp");
      u.searchParams.set("format", "json");
      u.searchParams.set("response_type", "vp_token id_token");
      u.searchParams.set("client_id", "dummy-client");
      u.searchParams.set("redirect_uri", "openid://");
      u.searchParams.set("scope", "openid");
      u.searchParams.set("state", state);
      u.searchParams.set("response_mode", "direct_post");

      const j = await getJSON(u.toString()); // ← “Failed to fetch” si CORS no está habilitado en Verifier
      const openid = j.openid_url ?? j.openid;
      setOpenidUrl(openid || "");

      try {
        const last = await getJSON(`${VERIFIER_API}/verifier/last-result`);
        setVerifierLast(last);
      } catch { /* noop */ }
    } catch (e) {
      alert("❌ " + e.message + "\n¿Has habilitado CORS en el Verifier para http://localhost:3000?");
    } finally {
      setBusy(false);
    }
  };

  // Presentar: Holder firma y ENVÍA VP al Verifier, luego navegamos a la vista que lee del Verifier
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
        password: "default",
        select: [index],
        send: true,
        auth: {
          redirect_uri: `${VERIFIER_API}/verifier/response`,
          state,
        },
      };

      const data = await postJSON(`${HOLDER_API}/wallet/present`, body);
      setAutoPresentResult(data);

      // Éxito si sent==true y post_status es código 200/302 (número o string) o “ok/success”
      const ps = String(data?.post_status ?? "").toLowerCase();
      const code = Number.isFinite(data?.post_status) ? data.post_status : NaN;
      const ok =
        data?.sent === true &&
        (code === 200 || code === 302 ||
          ps === "200" || ps === "302" ||
          ps.includes("ok") || ps.includes("success"));

      if (ok) {
        navigate("/verification-result");
      } else {
        try {
          const last = await getJSON(`${VERIFIER_API}/verifier/last-result`);
          setVerifierLast(last);
        } catch { /* noop */ }
        alert("⚠️ Presentación generada pero no enviada (revisa logs / post_status).");
      }
    } catch (e) {
      alert("❌ " + e.message);
    } finally {
      setBusy(false);
    }
  };

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
              readOnly={!holderDid}
            />
          </label>
          <div style={{ fontSize: 12, opacity: 0.8 }}>
            <div><b>Holder API:</b> {HOLDER_API}</div>
            <div><b>Verifier API:</b> {VERIFIER_API}</div>
          </div>
          <div>
            <button
              onClick={refreshCreds}
              disabled={busy || !(holderDid && holderDid.startsWith("did:jwk:"))}
              title={
                holderDid && holderDid.startsWith("did:jwk:")
                  ? "Refrescar credenciales"
                  : "Primero obtenemos el DID"
              }
            >
              🔄 Refrescar credenciales
            </button>
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
            <button
              onClick={receiveOffer}
              disabled={
                busy ||
                !offerUrl ||
                !(holderDid && holderDid.startsWith("did:jwk:"))
              }
              title={
                holderDid && holderDid.startsWith("did:jwk:")
                  ? "Recibir credencial externa"
                  : "Primero obtenemos el DID"
              }
            >
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

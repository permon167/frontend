// src/App.js
import React, { useEffect, useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { jwtDecode } from "jwt-decode";
import OID4VCIFlow from "./OID4VCIFlow.js";

import axios from "axios";
import { verifyCredentialJwt } from "@cef-ebsi/verifiable-credential";
import { QRCodeCanvas } from "qrcode.react";

// Fuerza el backend (evita depender de .env para esta parte)
const API_BASE = "http://localhost:8001";

// Helpers para bypassear el interstitial de ngrok en TODAS las llamdas
const withBypass = (url) =>
  url + (url.includes("?") ? "&" : "?") + "ngrok-skip-browser-warning=true";

const fetchBypass = (url, init = {}) => {
  const headers = {
    ...(init.headers || {}),
    "ngrok-skip-browser-warning": "true",
  };
  return fetch(withBypass(url), { ...init, headers });
};

// ==== Helpers UI para VP Preview ====
function decodeVpJwtSafe(vpJwt) {
  try {
    const payload = jwtDecode(vpJwt);
    const vcArray = payload?.vp?.verifiableCredential || [];
    const vcSummaries = vcArray.map((vc) => {
      try {
        const vcp = typeof vc === "string" ? jwtDecode(vc) : vc;
        const types = vcp?.vc?.type || vcp?.type || [];
        const subject =
          vcp?.sub ||
          vcp?.vc?.credentialSubject?.id ||
          vcp?.credentialSubject?.id ||
          "";
        return { types: Array.isArray(types) ? types : [types], subject };
      } catch {
        return { types: [], subject: "" };
      }
    });
    return { payload, vcSummaries };
  } catch {
    return null;
  }
}

function CredentialCard({
  credential,
  index,
  onDelete,
  onViewDetails,
  onVerifyEBSI,
  onPresentAuto,
  details,
  ebsiResult,
  ebsiLoading,
}) {
  const subject = credential.credentialSubject || {};
  const expiration = credential.expirationDate
    ? new Date(credential.expirationDate).toLocaleString("es-ES")
    : "—";
  const typesDisplay = Array.isArray(details?.types)
    ? details.types.join(", ")
    : details?.types ?? "";

  return (
    <div style={{ border: "1px solid #ccc", padding: "1rem", borderRadius: "8px", marginBottom: "1rem" }}>
      <h4>Credencial</h4>
      <p><strong>Nombre:</strong> {subject.firstName}</p>
      <p><strong>Apellido:</strong> {subject.lastName}</p>
      <p><strong>Email:</strong> {subject.emailAddress}</p>
      <p><strong>Expira:</strong> {expiration}</p>

      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button onClick={() => onDelete(index)} style={{ color: "crimson" }}>🗑️ Eliminar</button>
        <button onClick={() => onViewDetails(index)}>🔍 Ver detalle</button>
        <button onClick={() => onVerifyEBSI(index)}>✅ OIDC4VP</button>
        <button onClick={() => onPresentAuto(index)}>📤 Presentar (Auto OID4VP)</button>
      </div>

      {details && (
        <div style={{ marginTop: "1rem", backgroundColor: "#f8f8f8", padding: "1rem", borderRadius: "8px" }}>
          <h5>🧾 Detalles decodificados</h5>
          <p><strong>Issuer:</strong> {details.issuer}</p>
          <p><strong>Subject:</strong> {details.subject}</p>
          <p><strong>Tipos:</strong> {typesDisplay}</p>
          {details.expiration && (
            <p><strong>Expiración:</strong> {new Date(details.expiration * 1000).toLocaleString("es-ES")}</p>
          )}
        </div>
      )}

      {ebsiLoading && <p style={{ marginTop: 8 }}>⏳ Verificando con EBSI…</p>}
      {ebsiResult && (
        <div style={{
          marginTop: "0.75rem",
          border: `1px solid ${ebsiResult.ok ? "#2e7d32" : "#b71c1c"}`,
          background: ebsiResult.ok ? "#e8f5e9" : "#ffebee",
          padding: "0.75rem",
          borderRadius: 8
        }}>
          <strong>{ebsiResult.ok ? "✅ VC válida (EBSI local)" : "❌ VC inválida (EBSI local)"}</strong>
          <pre style={{ whiteSpace: "pre-wrap", fontSize: 12, overflow: "auto", marginTop: 8 }}>
{JSON.stringify(ebsiResult.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function VerificationResult() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const api = API_BASE.replace(/\/+$/, "");

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const success = urlParams.get("success");
    const state = urlParams.get("state");
    const code = urlParams.get("code");

    setResult({
      success: success === "true",
      state,
      code,
      message: success === "true" ? "Verificación exitosa" : "Verificación fallida",
    });

    (async () => {
      try {
        const r = await fetchBypass(`${api}/verifier/last-result`);
        if (r.ok) {
          const details = await r.json();
          setResult((prev) => ({ ...prev, details }));
        }
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    })();
  }, [api]);

  if (loading) return <div style={{ padding: "2rem" }}>⏳ Cargando resultado...</div>;

  return (
    <div style={{ padding: "2rem", fontFamily: "sans-serif" }}>
      <h2>📋 Resultado de Verificación EBSI (OIDC4VP)</h2>
      <div style={{
        padding: "1rem",
        backgroundColor: result?.success ? "#d4edda" : "#f8d7da",
        border: `1px solid ${result?.success ? "#c3e6cb" : "#f5c6cb"}`,
        borderRadius: "8px",
        marginBottom: "1rem"
      }}>
        <h3>{result?.success ? "✅ Verificación Exitosa" : "❌ Verificación Fallida"}</h3>
        <p><strong>Estado:</strong> {result?.state}</p>
        <p><strong>Código:</strong> {result?.code}</p>
      </div>

      {result?.details && (
        <div style={{ backgroundColor: "#f8f9fa", padding: "1rem", borderRadius: "8px", marginBottom: "1rem" }}>
          <h4>📊 Detalles técnicos:</h4>
          <pre style={{ fontSize: "12px", overflow: "auto" }}>
{JSON.stringify(result.details, null, 2)}
          </pre>
        </div>
      )}

      <button
        onClick={() => (window.location.href = "/")}
        style={{ padding: "10px 20px", backgroundColor: "#007bff", color: "white", border: "none", borderRadius: "4px" }}
      >
        🏠 Volver al inicio
      </button>
    </div>
  );
}

function WalletApp() {
  const [holderDid, setHolderDid] = useState(null);
  const [credentials, setCredentials] = useState([]);
  const [offerUri, setOfferUri] = useState("");
  const [message, setMessage] = useState("");
  const [decodedDetails, setDecodedDetails] = useState({});
  const [verificationStatus, setVerificationStatus] = useState("");

  // OIDC4VP (QR simple)
  const [openIdUrl, setOpenIdUrl] = useState("");

  // Estados para auto-presentación
  const [autoPresentLoading, setAutoPresentLoading] = useState(false);
  const [autoPresentResult, setAutoPresentResult] = useState(null);

  // Resultado + VP para vista previa
  const [verificationResult, setVerificationResult] = useState(null);
  const [vpToken, setVpToken] = useState("");

  // EBSI local por credencial (no enlazado en UI por defecto)
  const [ebsiLoadingIndex, setEbsiLoadingIndex] = useState(-1);
  const [ebsiResults, setEbsiResults] = useState({}); // { [index]: { ok, details } }

  axios.defaults.timeout = 15000;

  useEffect(() => {
    const init = async () => {
      let storedDid = localStorage.getItem("holderDid");
      if (!storedDid) {
        const res = await fetchBypass(`${API_BASE}/holder/create-did-jwk`, { method: "POST" });
        const data = await res.json();
        storedDid = data.did;
        localStorage.setItem("holderDid", storedDid);
      }
      setHolderDid(storedDid);
    };
    init();
  }, []);

  const receiveOid4vc = async () => {
    if (!offerUri || !holderDid) {
      alert("Faltan campos");
      return;
    }
    try {
      const res = await fetchBypass(`${API_BASE}/holder/receive-oid4vc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credential_offer_uri: offerUri,
          holder_did: holderDid,
          password: "default",
        }),
      });
      await res.json();
      if (!res.ok) {
        alert("❌ Error al recibir la credencial");
        return;
      }
      await loadAllCredentials();
      setMessage("💾 Credencial guardada en la wallet");
    } catch (err) {
      console.error("❌ Error general:", err);
      alert("Error inesperado al recibir la credencial");
    }
  };

  const loadAllCredentials = async () => {
    try {
      const res = await fetchBypass(`${API_BASE}/holder/credentials`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          holder_did: holderDid,
          password: "default",
        }),
      });
      const data = await res.json();
      const decodedCreds = (data.credentials || []).map((c) => {
        const jwt = c.credential || c;
        return jwtDecode(jwt);
      });
      setCredentials(decodedCreds);
    } catch (err) {
      console.error("❌ No se pudieron cargar credenciales:", err);
    }
  };

  const handleDeleteCredential = async (index) => {
    try {
      const res = await fetchBypass(`${API_BASE}/holder/delete-credential`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          holder_did: holderDid,
          password: "default",
          index,
        }),
      });
      const result = await res.json();
      if (res.ok) {
        alert("Credencial eliminada");
        await loadAllCredentials();
      } else {
        alert("❌ Error al eliminar: " + result.error);
      }
    } catch (err) {
      alert("❌ Error inesperado al eliminar la credencial");
    }
  };

  const handleViewDetails = async (index) => {
    try {
      const res = await fetchBypass(`${API_BASE}/holder/decode-credential`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          holder_did: holderDid,
          password: "default",
          index,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setDecodedDetails((prev) => ({ ...prev, [index]: data }));
      } else {
        alert("❌ Error al decodificar credencial: " + data.error);
      }
    } catch (err) {
      alert("❌ Error inesperado al decodificar credencial");
      console.error(err);
    }
  };

  // --- OIDC4VP: petición robusta al JSON con openid_url + bypass ngrok ---
  const handleVerifyWithEBSI = async () => {
    try {
      setVerificationStatus("🔄 Preparando solicitud OIDC4VP…");
      console.log("API_BASE =", API_BASE);

      const u1 = `${API_BASE}/authorize/openid?flow=vp&format=json`;
      const u2 = `${API_BASE}/authorize?flow=vp&format=json`;

      let openid = "";

      // 1) Intento principal: /authorize/openid?flow=vp
      try {
        const r = await fetchBypass(u1, {
          method: "GET",
          headers: { Accept: "application/json" },
          cache: "no-store",
        });
        const raw = await r.text();
        console.log("[authorize/openid] status", r.status, "raw:", raw);

        if (r.ok && raw) {
          let data;
          try { data = JSON.parse(raw); } catch { data = {}; }
          openid = String(data.openid_url || data.openid || data.location || "").trim();
          if (openid.startsWith('"') && openid.endsWith('"')) openid = openid.slice(1, -1);
        }
      } catch (e) {
        console.warn("Fallo en /authorize/openid:", e);
      }

      // 2) Fallback: /authorize?flow=vp&format=json
      if (!openid || !openid.startsWith("openid://")) {
        try {
          const r2 = await fetchBypass(u2, {
            method: "GET",
            headers: { Accept: "application/json" },
            cache: "no-store",
          });
          const raw2 = await r2.text();
          console.log("[authorize?format=json] status", r2.status, "raw:", raw2);

          if (r2.ok && raw2) {
            let data2;
            try { data2 = JSON.parse(raw2); } catch { data2 = {}; }
            let candidate = String(data2.openid_url || data2.openid || data2.location || "").trim();
            if (candidate.startsWith('"') && candidate.endsWith('"')) candidate = candidate.slice(1, -1);
            if (candidate.startsWith("openid://")) openid = candidate;
          }
        } catch (e) {
          console.warn("Fallo en /authorize?format=json:", e);
        }
      }

      console.log("computed openid =", openid);
      if (!openid || !openid.startsWith("openid://")) {
        setVerificationStatus("❌ Respuesta inválida: falta openid:// (revisa consola → raw)");
        return;
      }

      setOpenIdUrl(openid);
      setVerificationStatus("📱 Escanea el QR con tu wallet para continuar");
      // Si quieres abrir automáticamente en móvil:
      // if (/iPhone|iPad|iPod|Android/i.test(navigator.userAgent)) window.location.href = openid;
    } catch (e) {
      console.error("❌ Error OIDC4VP:", e);
      setVerificationStatus("❌ Error al iniciar la verificación con OIDC4VP");
    }
  };

  // Auto-presentación: intenta /wallet/present; si 404, fallback a /presentations/auto-from-authorize
  const handlePresentAuto = async (index) => {
    setAutoPresentLoading(true);
    setAutoPresentResult(null);
    setVerificationResult(null);
    setVpToken("");
    try {
      const body = {
        authorize_url: `${API_BASE}/authorize/openid?flow=vp`,
        holder_did: holderDid,
        password: "default",
        select: [Number(index)],
      };

      // 1º intento: endpoint nuevo
      let res = await fetchBypass(`${API_BASE}/wallet/present`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      // Fallback: endpoint antiguo si el nuevo no existe
      if (res.status === 404) {
        res = await fetchBypass(`${API_BASE}/presentations/auto-from-authorize`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            verifier_base: API_BASE,
            holder_did: holderDid,
            password: "default",
            index: Number(index),
          }),
        });
      }

      const data = await res.json().catch(() => ({}));
      if (data.vp_jwt) setVpToken(String(data.vp_jwt));

      if (res.ok) {
        setAutoPresentResult({
          success: true,
          status: data.status || res.status,
          response: "Presentation sent from backend",
          data,
        });
        const verdict = data?.verdict;
        if (verdict && typeof verdict.ok === "boolean") {
          setVerificationResult(verdict);
          setMessage(verdict.ok ? "✅ Verificación correcta" : "❌ Verificación fallida");
        } else {
          setMessage("ℹ️ Presentación enviada. Revisa el veredicto o la redirección.");
        }
      } else {
        setAutoPresentResult({
          success: false,
          status: res.status,
          error: data.error || "Error en auto-presentación",
          data,
        });
        setVerificationResult({ ok: false, message: data.error || "Error en auto-presentación" });
      }
    } catch (err) {
      setAutoPresentResult({ success: false, error: err.message });
      setVerificationResult({ ok: false, message: err.message });
      setMessage(`❌ Error en auto-presentación: ${err.message}`);
    } finally {
      setAutoPresentLoading(false);
    }
  };

  // Verificación EBSI local (VC-JWT) por índice (conservado por si se usa)
  const verifyVcLocal = async (index) => {
    setEbsiLoadingIndex(index);
    try {
      const { data } = await axios.post(
        withBypass(`${API_BASE}/holder/jwt-credential`),
        { holder_did: holderDid, password: "default", index },
        { headers: { "ngrok-skip-browser-warning": "true" } }
      );
      const vcJwt = data?.jwt;
      if (!vcJwt) throw new Error("No se obtuvo el VC-JWT");

      // Estructura básica de JWT
      try {
        const base64Header = vcJwt.split('.')[0];
        JSON.parse(atob(base64Header));
        const base64Payload = vcJwt.split('.')[1];
        JSON.parse(atob(base64Payload));
      } catch {
        throw new Error("JWT malformado: no se puede decodificar");
      }

      const result = await verifyCredentialJwt(vcJwt, {
        hosts: ["api-pilot.ebsi.eu"],
        scheme: "ebsi",
        network: { name: "pilot", isOptional: false },
        services: {
          "did-registry": "v5",
          "trusted-issuers-registry": "v5",
          "trusted-policies-registry": "v3",
          "trusted-schemas-registry": "v3",
        },
      }, {
        skipAccreditationsValidation: true,
        skipStatusValidation: true,
      });

      setEbsiResults((prev) => ({ ...prev, [index]: { ok: true, details: result } }));
    } catch (err) {
      let errorDetails = { error: err?.message || String(err) };
      if (err.message && err.message.includes("kid")) {
        errorDetails = {
          error: "VC no compatible con EBSI",
          reason: "Falta el header 'kid' requerido por EBSI",
          suggestion: "El header 'kid' debe contener el DID del emisor con el identificador del método de verificación.",
          original_error: err.message,
          ebsi_compatible: false
        };
      } else if (err.message && err.message.includes("JWT header")) {
        errorDetails = {
          error: "Error en headers JWT",
          reason: "Los headers del JWT no cumplen con los requisitos EBSI",
          suggestion: "Verifica headers (alg, kid, typ)",
          original_error: err.message,
          ebsi_compatible: false
        };
      } else if (err.message && err.message.includes("algorithm")) {
        errorDetails = {
          error: "Algoritmo no soportado",
          reason: "Algoritmo no compatible",
          suggestion: "EBSI suele requerir ES256/ES256K/EdDSA",
          original_error: err.message,
          ebsi_compatible: false
        };
      } else if (err.message && (err.message.includes("issuer") || err.message.includes("iss"))) {
        errorDetails = {
          error: "Emisor no válido",
          reason: "iss no válido/registrado",
          suggestion: "El emisor debe ser un DID válido",
          original_error: err.message,
          ebsi_compatible: false
        };
      }
      setEbsiResults((prev) => ({ ...prev, [index]: { ok: false, details: errorDetails } }));
    } finally {
      setEbsiLoadingIndex(-1);
    }
  };

  // === UI ===
  return (
    <div style={{ padding: "2rem", fontFamily: "sans-serif" }}>
      <h2>📱 Holder Wallet</h2>

      {message && (
        <div style={{
          padding: "10px",
          backgroundColor: message.startsWith("❌") ? "#f8d7da" : (message.startsWith("⚠️") ? "#fff3cd" : "#e2f0d9"),
          border: "1px solid #ddd",
          borderRadius: "4px",
          marginBottom: "1rem",
        }}>
          {message}
        </div>
      )}

      {verificationStatus && (
        <div style={{
          padding: "10px",
          backgroundColor: "#d1ecf1",
          border: "1px solid #bee5eb",
          borderRadius: "4px",
          marginBottom: "1rem",
        }}>
          {verificationStatus}
        </div>
      )}

      <p><strong>Mi DID:</strong><br />{holderDid || "Generando..."}</p>

      <hr />
      <h3>Recibir credencial desde emisor externo (OpenID4VCI)</h3>
      <input
        type="text"
        placeholder="Pega el credential_offer_uri"
        value={offerUri}
        onChange={(e) => setOfferUri(e.target.value)}
        style={{ width: "100%" }}
      />
      <br /><br />
      <button onClick={receiveOid4vc}>📥 Recibir credencial externa</button>

      <hr />
      <h3>Credenciales guardadas</h3>
      <div style={{ display: "flex", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
        <button onClick={loadAllCredentials}>📚 Mostrar todas</button>
        <button onClick={handleVerifyWithEBSI}>✅ OIDC4VP</button>
      </div>

      {/* Bloque QR OIDC4VP (si se obtuvo openid:// por JSON) */}
      {openIdUrl && (
        <div style={{ marginTop: 16, padding: 12, border: "1px solid #ddd", borderRadius: 8 }}>
          <h4>Escanea con tu wallet OIDC4VP</h4>
          <QRCodeCanvas value={openIdUrl} size={280} />
          <p style={{ wordBreak: "break-all", fontSize: 12, marginTop: 8 }}>{openIdUrl}</p>

          <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
            <button onClick={() => setOpenIdUrl("")}>🧹 Ocultar QR</button>
            <button onClick={() => navigator.clipboard.writeText(openIdUrl)}>📋 Copiar enlace</button>
          </div>
        </div>
      )}

      <div style={{ marginTop: "1rem" }}>
        {credentials.length > 0 ? (
          credentials.map((cred, idx) => (
            <CredentialCard
              key={idx}
              credential={cred}
              index={idx}
              onDelete={handleDeleteCredential}
              onViewDetails={handleViewDetails}
              onVerifyEBSI={handleVerifyWithEBSI}
              onPresentAuto={handlePresentAuto}
              details={decodedDetails[idx]}
              ebsiResult={ebsiResults[idx]}
              ebsiLoading={ebsiLoadingIndex === idx}
            />
          ))
        ) : (
          <p>🎃 No hay credenciales</p>
        )}
      </div>

      {/* Resultado de auto-presentación */}
      {autoPresentLoading && (
        <div style={{ marginTop: "1rem", padding: "1rem", backgroundColor: "#fff3cd", border: "1px solid #ffeaa7", borderRadius: "8px" }}>
          <p>⏳ Enviando presentación automática...</p>
        </div>
      )}

      {autoPresentResult && (
        <div style={{
          marginTop: "1rem",
          padding: "1rem",
          backgroundColor: autoPresentResult.success ? "#d4edda" : "#f8d7da",
          border: `1px solid ${autoPresentResult.success ? "#c3e6cb" : "#f5c6cb"}`,
          borderRadius: "8px"
        }}>
          <h4>{autoPresentResult.success ? "✅ Auto-presentación exitosa" : "❌ Error en auto-presentación"}</h4>
          {autoPresentResult.error && <p><strong>Error:</strong> {autoPresentResult.error}</p>}
          {autoPresentResult.status && <p><strong>Status:</strong> {autoPresentResult.status}</p>}
          <details style={{ marginTop: "0.5rem" }}>
            <summary>Ver detalles técnicos</summary>
            <pre style={{ whiteSpace: "pre-wrap", fontSize: 12, overflow: "auto", marginTop: 8 }}>
{JSON.stringify(autoPresentResult, null, 2)}
            </pre>
          </details>
        </div>
      )}

      {/* Badge de verificación y resumen */}
      {verificationResult && (
        <div style={{
          marginTop: "1rem",
          padding: "12px",
          borderRadius: 10,
          border: `1px solid ${verificationResult.ok ? "#22c55e" : "#ef4444"}`,
          background: verificationResult.ok ? "#052e16" : "#3f1d1d",
          color: "#e5e7eb"
        }}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <span style={{
              display:"inline-block", width:10, height:10, borderRadius:"50%",
              background: verificationResult.ok ? "#22c55e" : "#ef4444"
            }} />
            <strong>
              {verificationResult.ok ? "✔ Verificación correcta" : "✖ Verificación fallida"}
            </strong>
          </div>
          <div style={{marginTop:6, opacity:0.9}}>
            {verificationResult.message || (verificationResult.ok ? "VP y VC válidas" : "Revisa el detalle")}
          </div>

          {/* Resumen audit-friendly */}
          <div style={{marginTop:10, padding:12, border:"1px solid #334155", borderRadius:10}}>
            <div style={{display:"grid", gridTemplateColumns:"140px 1fr", gap:6, fontSize:13}}>
              <div><b>aud</b></div><div style={{wordBreak:"break-all"}}>{verificationResult.vp?.aud || "—"}</div>
              <div><b>nonce</b></div><div style={{wordBreak:"break-all"}}>{verificationResult.vp?.nonce || "—"}</div>
              <div><b>iss/sub</b></div><div style={{wordBreak:"break-all"}}>{verificationResult.vp?.iss || "—"}</div>
              <div><b>iat/exp</b></div>
              <div>
                {verificationResult.vp?.iat ? new Date(verificationResult.vp.iat*1000).toLocaleString("es-ES") : "—"}
                {" → "}
                {verificationResult.vp?.exp ? new Date(verificationResult.vp.exp*1000).toLocaleString("es-ES") : "—"}
              </div>
            </div>

            <h4 style={{marginTop:10}}>VCs verificadas</h4>
            {(verificationResult.vc_verifications || []).map((v,i)=>(
              <div key={i} style={{display:"flex",gap:8, alignItems:"center"}}>
                <span style={{
                  display:"inline-block", width:8, height:8, borderRadius:"50%",
                  background: v.verified ? "#22c55e" : "#ef4444"
                }} />
                <code>VC[{v.index}]</code> — {v.verified ? "válida" : `inválida: ${v.error || "motivo no disponible"}`}
              </div>
            ))}

            {!verificationResult.pex_ok && (verificationResult.pex_errors || []).length > 0 && (
              <>
                <h4 style={{marginTop:10}}>Errores PEX</h4>
                <ul style={{marginTop:4}}>
                  {(verificationResult.pex_errors||[]).map((e,idx)=><li key={idx}>{e}</li>)}
                </ul>
              </>
            )}
          </div>
        </div>
      )}

      {/* Vista previa de la VP (resumen + copiar/descargar) */}
      {vpToken && (
        <div style={{ marginTop: 16, padding: 12, border: "1px solid #334155", borderRadius: 8, background: "#0b1220", color:"#e2e8f0" }}>
          <h4>🧾 Vista previa de la Presentación</h4>
          {(() => {
            const decoded = decodeVpJwtSafe(vpToken);
            if (!decoded) return <div>No se pudo decodificar la VP-JWT.</div>;
            const p = decoded.payload;
            return (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "130px 1fr", gap: 6, fontSize: 13 }}>
                  <div><strong>iss</strong></div><div style={{wordBreak:"break-all"}}>{p.iss}</div>
                  <div><strong>sub</strong></div><div style={{wordBreak:"break-all"}}>{p.sub}</div>
                  <div><strong>aud</strong></div><div style={{wordBreak:"break-all"}}>{p.aud}</div>
                  <div><strong>nonce</strong></div><div style={{wordBreak:"break-all"}}>{p.nonce}</div>
                  <div><strong>iat</strong></div><div>{p.iat ? new Date(p.iat*1000).toLocaleString("es-ES") : "—"}</div>
                  <div><strong>exp</strong></div><div>{p.exp ? new Date(p.exp*1000).toLocaleString("es-ES") : "—"}</div>
                </div>

                <h5 style={{ marginTop: 10 }}>Credenciales en la VP</h5>
                {decoded.vcSummaries.length === 0 ? "—" : (
                  <ul>
                    {decoded.vcSummaries.map((s, i) => (
                      <li key={i}>
                        <strong>Tipos:</strong> {(s.types || []).join(", ") || "—"} · <strong>Subject:</strong> {s.subject || "—"}
                      </li>
                    ))}
                  </ul>
                )}

                <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
                  <button onClick={() => navigator.clipboard.writeText(vpToken)}>📋 Copiar VP-JWT</button>
                  <button onClick={() => {
                    const blob = new Blob([vpToken], { type: "text/plain" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url; a.download = "vp.jwt";
                    a.click();
                    URL.revokeObjectURL(url);
                  }}>💾 Descargar</button>
                </div>

                <details style={{ marginTop: 10 }}>
                  <summary>Ver VP completa (JSON)</summary>
                  <pre style={{ whiteSpace: "pre-wrap", fontSize: 12, overflow: "auto", marginTop: 8 }}>
{JSON.stringify(p, null, 2)}
                  </pre>
                </details>
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
}

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<WalletApp />} />
        <Route path="/dbc-test" element={<OID4VCIFlow />} />
        <Route path="/verification-result" element={<VerificationResult />} />
      </Routes>
    </Router>
  );
}

export default App;

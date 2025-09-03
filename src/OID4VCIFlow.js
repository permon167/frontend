import React, { useEffect, useState } from "react";

const OID4VCIFlow = () => {
  const [status, setStatus] = useState("Esperando...");
  const [credential, setCredential] = useState(null);

  useEffect(() => {
    const runFlow = async () => {
      try {
        setStatus("Solicitando oferta de credencial...");

        const offerUrl = "https://ssi.dutchblockchaincoalition.org/agent/.well-known/openid-credential-offer";
        const offerResponse = await fetch(offerUrl);
        const offer = await offerResponse.json();

        const tokenEndpoint = offer.credential_issuer_metadata.token_endpoint;
        const credentialEndpoint = offer.credential_issuer_metadata.credential_endpoint;
        const credentialType = offer.credential_issuer_metadata.credentials_supported[0].id;
        const format = offer.credential_issuer_metadata.credentials_supported[0].format;
        const preAuthorizedCode = offer.credential_offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"];

        setStatus("Solicitando access_token...");

        const tokenRes = await fetch(tokenEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": preAuthorizedCode,
          }),
        });

        const tokenData = await tokenRes.json();
        const accessToken = tokenData.access_token;

        setStatus("Solicitando credencial...");

        const credRes = await fetch(credentialEndpoint, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            format: format,
            types: [credentialType],
          }),
        });

        const credentialJson = await credRes.json();
        setCredential(credentialJson);
        setStatus("✅ Credencial recibida con éxito.");
      } catch (error) {
        console.error(error);
        setStatus("❌ Error en el flujo de emisión.");
      }
    };

    runFlow();
  }, []);

  return (
    <div style={{ padding: "2rem" }}>
      <h2>Flujo OID4VCI con DBC</h2>
      <p>{status}</p>
      {credential && (
        <pre style={{ textAlign: "left", whiteSpace: "pre-wrap" }}>
          {JSON.stringify(credential, null, 2)}
        </pre>
      )}
    </div>
  );
};

export default OID4VCIFlow;

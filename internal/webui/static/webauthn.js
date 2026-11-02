

// webauthnJSON converts between the WebAuthn JSON forms the server speaks
// and the objects navigator.credentials uses: natively where the browser
// can, and otherwise by decoding and encoding the base64url fields
// (WebAuthn Level 3, sections 5.1.8 and 5.1.9).
export const webauthnJSON = (() => {
  const toBytes = (s) => {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  };
  const toB64URL = (buf) => {
    if (!buf) return null;
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const descriptors = (list) => list?.map((d) => ({ ...d, id: toBytes(d.id) }));
  const PKC = window.PublicKeyCredential;

  return {
    creationOptions(json) {
      if (PKC?.parseCreationOptionsFromJSON) return PKC.parseCreationOptionsFromJSON(json);
      return { ...json, challenge: toBytes(json.challenge), user: { ...json.user, id: toBytes(json.user.id) }, excludeCredentials: descriptors(json.excludeCredentials) };
    },
    requestOptions(json) {
      if (PKC?.parseRequestOptionsFromJSON) return PKC.parseRequestOptionsFromJSON(json);
      return { ...json, challenge: toBytes(json.challenge), allowCredentials: descriptors(json.allowCredentials) };
    },
    credential(cred) {
      if (typeof cred.toJSON === "function") return cred.toJSON();
      const r = cred.response;
      const response = { clientDataJSON: toB64URL(r.clientDataJSON) };
      if (r.attestationObject) {
        response.attestationObject = toB64URL(r.attestationObject);
        if (r.getAuthenticatorData) response.authenticatorData = toB64URL(r.getAuthenticatorData());
        if (r.getTransports) response.transports = r.getTransports();
        if (r.getPublicKeyAlgorithm) response.publicKeyAlgorithm = r.getPublicKeyAlgorithm();
      } else {
        response.authenticatorData = toB64URL(r.authenticatorData);
        response.signature = toB64URL(r.signature);
        response.userHandle = toB64URL(r.userHandle);
      }
      return {
        id: cred.id, rawId: toB64URL(cred.rawId), type: cred.type,
        authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
        clientExtensionResults: cred.getClientExtensionResults(),
        response,
      };
    },
  };
})();

// ---------- boot and navigation ----------

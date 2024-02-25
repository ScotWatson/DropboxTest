/*
(c) 2024 Scot Watson  All Rights Reserved
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Creates a GET Request to the specified endpoint
function createRequestGET(endpoint, headers) {
  return new self.Request(endpoint, {
    method: "GET",
    headers: headers,
    mode: "cors",
    credentials: "same-origin",
    cache: "default",
    redirect: "follow",
    referrer: "about:client",
    referrerPolicy: "",
    integrity: "",
    keepalive: "",
    signal: null,
    priority: "auto",
  });
}

// Creates a POST Request to the specified endpoint
function createRequestPOST(endpoint, body, headers) {
  return new self.Request(endpoint, {
    method: "POST",
    headers: headers,
    body: body,
    mode: "cors",
    credentials: "same-origin",
    cache: "default",
    redirect: "follow",
    referrer: "about:client",
    referrerPolicy: "",
    integrity: "",
    keepalive: "",
    signal: null,
    priority: "auto",
  });
}

// This web application is a "client", per the definition in Section 1.1 of RFC 6749.
// Specifically, it is a "user-agent-based application", and therefore a "public" client, per the definitions in Section 2.1 of RFC 6749.
// Section 1.1 of RFC 6749 specifies the following four grant types:
// - authorization code
// - implicit
// - resource owner password credentials
// - client credentials

const urlThis = new self.URL(window.location);
const paramsThis = urlThis.searchParams;
const strThisFragment = urlThis.hash.substring(1);

// Below is the "Client Identifier" referred to in Section 2.2 of RFC 6749. This is also referred to by some as the "App Id".
// All methods in the library require the client identifier and therefore assume the client is registered. Unregistered clients per Section 2.4 of RFC 6749 are not supported.
let strClientId;
// Below is the "Authorization Endpoint" per Section 3 of RFC 6749. Section 3.1 of RFC 6749 provides details.
let urlAuthorizationEndpoint;
// Below is the "Token Endpoint" per Section 3 of RFC 6749. Section 3.2 of RFC 6749 provides details.
let urlTokenEndpoint;
// Below is the "Redirect Endpoint" per Section 3 of RFC 6749. Section 3.1.2 of RFC 6749 provides details. It is taken to be the current location.
const urlRedirectEndpoint = new self.URL(urlThis.origin + urlThis.pathname);

export function initialize(args) {
  ({ strClientId, urlAuthorizationEndpoint, urlTokenEndpoint } = args);
}

let strAccessToken = "";
let strRefreshToken = "";

let callbackAccessToken;
let callbackRefreshToken;

export function setCallbackAccessToken(callback) {
  callbackAccessToken = callback;
}
export function setCallbackRefreshToken(callback) {
  callbackRefreshToken = callback;
}

export function setAccessToken(strToken) {
  strAccessToken = strToken;
  if (typeof callbackAccessToken === "function") {
    callbackAccessToken(strAccessToken);
  }
}
export function setRefreshToken(strToken) {
  strRefreshToken = strToken;
  if (typeof callbackAccessToken === "function") {
    callbackRefreshToken(strRefreshToken);
  }
}
export function getAccessToken() {
  return strAccessToken;
}
export function getRefreshToken() {
  return strRefreshToken;
}

export function parseRedirectParameters() {
  const auth_mode = window.sessionStorage.getItem("auth_mode");
  if (auth_mode) {
    switch (auth_mode) {
      case "PKCE Access": {
        // PKCE flow redirect callback - access token
        if (paramsThis.has("code")) {
          alert("PKCE flow redirect callback - access token");
          const authorization_code = paramsThis.get("code");
          const code_verifier = window.sessionStorage.getItem("code_verifier");
          (async function () {
            setAccessToken(await tokenAccessPKCE(authorization_code, code_verifier));
          })();
          window.sessionStorage.removeItem("auth_mode");
          window.sessionStorage.removeItem("code_verifier");
          window.history.replaceState(null, "", urlRedirectEndpoint);
        }
      }
        break;
      case "PKCE Refresh": {
        // PKCE flow redirect callback - refresh token
        if (paramsThis.has("code")) {
          alert("PKCE flow redirect callback - refresh token");
          const authorization_code = paramsThis.get("code");
          const code_verifier = window.sessionStorage.getItem("code_verifier");
          (async function () {
            const { strNewAccessToken, strNewRefreshToken } = await tokenRefreshPKCE(authorization_code, code_verifier);
            setAccessToken(strNewAccessToken);
            setRefreshToken(strNewRefreshToken);
          })();
          window.sessionStorage.removeItem("auth_mode");
          window.sessionStorage.removeItem("code_verifier");
          window.history.replaceState(null, "", urlRedirectEndpoint);
        }
      }
        break;
      case "Implicit Access": {
        const paramsThisFragment = new self.URLSearchParams(strThisFragment);
        if (paramsThisFragment.get("access_token")) {
          // Implicit flow redirect callback - access token
          alert("Implicit flow redirect callback - access token");
          setAccessToken(paramsThisFragment.get("access_token"));
          window.sessionStorage.removeItem("auth_mode");
          window.history.replaceState(null, "", urlRedirectEndpoint);
        }
      }
        break;
      // Implicit flow redirect callback - refresh token - NOT POSSIBLE
      default: {
        console.error("Invalid Authorization mode.");
      }
    };
  }
}

function strRaw32Random() {
  const buffer = new Uint8Array(32);
  self.crypto.getRandomValues(buffer);
  return rawFromBytes(buffer);
}
function bytesFromRaw(strRaw) {
  const ret = new Uint8Array(strRaw.length);
  for (let i = 0; i < strRaw.length; ++i) {
    ret[i] = strRaw.charCodeAt(i);
  }
  return ret.buffer;
}
function rawFromBytes(bytes) {
  const buffer = new Uint8Array(bytes);
  let ret = "";
  for (const byte of buffer) {
    ret += String.fromCharCode(byte);
  }
  return ret;
}
function base64UrlEncode(strRaw) {
  return btoa(strRaw).replaceAll("+", "-").replaceAll("/", "_");
}
function base64UrlDecode(strBase64URL) {
  const strBase64 = strBase64URL.replaceAll("-", "+").replaceAll("_", "/");
  return atob(strBase64);
}
async function tokenAccessPKCE(authorization_code, verification_code) {
  // Step (C) of Section 1.1 of RFC7636
  const params = new self.URLSearchParams([
    ["code", authorization_code ],
    ["grant_type", "authorization_code" ],
    ["redirect_uri", urlRedirectEndpoint ],
    ["code_verifier", verification_code ],
    ["client_id", strClientId ],
  ]);
  const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST(urlTokenEndpoint, blobBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  // Step (D) of Section 1.1 of RFC7636
  const objResp = JSON.parse(jsonRespBody);
  console.log(objResp);
  return objResp["access_token"];
}
async function tokenRefreshPKCE(authorization_code, verification_code) {
  const params = new self.URLSearchParams([
    ["code", authorization_code ],
    ["grant_type", "authorization_code" ],
    ["redirect_uri", urlRedirectEndpoint ],
    ["code_verifier", verification_code ],
    ["client_id", strClientId ],
  ]);
  const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST(urlTokenEndpoint, blobBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  const objResp = JSON.parse(jsonRespBody);
  console.log(objResp);
  return {
    strNewAccessToken: objResp["access_token"],
    strNewRefreshToken: objResp["refresh_token"],
  };
}
export async function tokenAccessFromRefreshPKCE() {
  const params = new self.URLSearchParams([
    ["grant_type", "refresh_token" ],
    ["refresh_token", strRefreshToken ],
    ["client_id", strClientId ],
  ]);
  const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST(urlTokenEndpoint, blobBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  const objResp = JSON.parse(jsonRespBody);
  console.log(objResp);
  return objResp["access_token"];
}
export async function getPKCEAccessToken() {
  // Step (A) of Section 1.1 of RFC7636
  const code_verifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
  const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
  const code_challenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
  window.sessionStorage.setItem("code_verifier", code_verifier);
  const params = new URLSearchParams([
    [ "client_id", strClientId ],
    [ "redirect_uri", urlRedirectEndpoint ],
    [ "response_type", "code" ],
    [ "code_challenge", code_challenge ],
    [ "code_challenge_method", "S256" ],
  ]);
  const urlAuthorize = new URL(urlAuthorizationEndpoint + "?" + params);
  window.sessionStorage.setItem("auth_mode", "PKCE Access");
  window.location = urlAuthorize;
  // Step (B) of Section 1.1 of RFC7636 occurs on the server. It will send a redirect.
}
export async function getImplicitAccessToken() {
  const params = new URLSearchParams([
    [ "client_id", strClientId ],
    [ "redirect_uri", urlRedirectEndpoint ],
    [ "response_type", "token" ],
  ]);
  const urlAuthorize = new URL(urlAuthorizationEndpoint + "?" + params);
  window.sessionStorage.setItem("auth_mode", "Implicit Access");
  window.location = urlAuthorize;
}
export async function getPKCERefreshToken() {
  const code_verifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
  const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
  const code_challenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
  window.sessionStorage.setItem("code_verifier", code_verifier);
  const params = new URLSearchParams([
    [ "client_id", strClientId ],
    [ "redirect_uri", urlRedirectEndpoint ],
    [ "token_access_type", "offline" ],
    [ "response_type", "code" ],
    [ "code_challenge", code_challenge ],
    [ "code_challenge_method", "S256" ],
  ]);
  const urlAuthorize = new URL(urlAuthorizationEndpoint + "?" + params);
  window.sessionStorage.setItem("auth_mode", "PKCE Refresh");
  window.location = urlAuthorize;
}
let urlRevokeEndpoint;
export function setRevokeEndpoint(urlNewRevokeEndpoint) {
  urlRevokeEndpoint = urlNewRevokeEndpoint;
}
export function getRevokeEndpoint() {
  return urlRevokeEndpoint;
}
export async function revokeToken(strToken) {
  const headers = [ [ "Authorization", "Bearer " + strToken ] ];
  const reqRevokeToken = createRequestPOST(urlRevokeEndpoint, null, headers);
  const respRevokeToken = await fetch(reqRevokeToken);
  console.log(respRevokeToken);
  if (respRevokeToken.status === 200) {
    console.log("Token Revoked");
    setAccessToken("");
    setRefreshToken("");
  } else {
    console.log("Token Not Revoked");
  }
}

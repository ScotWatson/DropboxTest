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

// This web application is a "client", per the definition in Section 1.1 of RFC6749.
// Specifically, it is a "user-agent-based application", and therefore a "public" client, per the definitions in Section 2.1 of RFC6749.
// Section 1.1 of RFC6749 specifies the following four grant types:
// - authorization code
// - implicit
// - resource owner password credentials
// - client credentials

const selfURL = new self.URL(window.location);
const selfURLParams = selfURL.searchParams;
const selfURLFragment = selfURL.hash.substring(1);

// Below is the "Redirect Endpoint" per Section 3 of RFC6749. Section 3.1.2 of RFC6749 provides details. It is taken to be the current location.
const redirectEndpoint = new self.URL(selfURL.origin + selfURL.pathname);

function coerseToString(args) {
  if (typeof args === "object" && args !== null) {
    return args.toString();
  } else if (typeof args !== "string") {
    return args;
  } else {
    throw "Failed to coerse to string";
  }
}
// Each of the "retrieveToken" functions below performs redirection to obtain tokens.  This function will cause the page to refresh.
// These functions each require:
//   "Authorization Endpoint"
//   "Token Endpoint"
// The "Authorization Endpoint" per Section 3 of RFC6749. Section 3.1 of RFC6749 provides details.
// The "Token Endpoint" per Section 3 of RFC6749. Section 3.2 of RFC6749 provides details.

export async retrieveTokenPKCEAccess(args) {
  const { authorizationEndpoint, tokenEndpoint } = args;
  const strAuthorizationEndpoint = coerseToString(authorizationEndpoint);
  const strTokenEndpoint = coerseToString(tokenEndpoint);
  // Step (A) of Section 1.1 of RFC7636
  const nonce = base64UrlEncode(strRaw32Random()).slice(0, -1);
  const codeVerifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
  const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(codeVerifier));
  const codeChallenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
  const params = new URLSearchParams([
    [ "client_id", this.#clientId ],
    [ "redirect_uri", redirectEndpoint ],
    [ "response_type", "code" ],
    [ "code_challenge", codeChallenge ],
    [ "code_challenge_method", "S256" ],
    [ "state", nonce ],
  ]);
  const authorizeURL = new URL(strAuthorizationEndpoint + "?" + params);
  window.sessionStorage.setItem("OAuth2", {
    grantType: "PKCE Access",
    codeVerifier: codeVerifier,
    tokenEndpoint: strTokenEndpoint,
    state: nonce,
  });
  window.location = authorizeURL;
  // Step (B) of Section 1.1 of RFC7636 occurs on the server. It will send a redirect.
}
export async retrieveTokenPKCERefresh(args) {
  const { authorizationEndpoint, tokenEndpoint } = args;
  const strAuthorizationEndpoint = coerseToString(authorizationEndpoint);
  const strTokenEndpoint = coerseToString(tokenEndpoint);
  // Step (A) of Section 1.1 of RFC7636
  const nonce = base64UrlEncode(strRaw32Random()).slice(0, -1);
  const codeVerifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
  const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(codeVerifier));
  const codeChallenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
  const params = new URLSearchParams([
    [ "client_id", this.#clientId ],
    [ "redirect_uri", redirectEndpoint ],
    [ "token_access_type", "offline" ],
    [ "response_type", "code" ],
    [ "code_challenge", code_challenge ],
    [ "code_challenge_method", "S256" ],
    [ "state", nonce ],
  ]);
  const authorizeURL = new URL(strAuthorizationEndpoint + "?" + params);
  window.sessionStorage.setItem("OAuth2", {
    grantType: "PKCE Refresh",
    codeVerifier: codeVerifier,
    tokenEndpoint: strTokenEndpoint,
    state: nonce,
  });
  window.location = authorizeURL;
  // Step (B) of Section 1.1 of RFC7636 occurs on the server. It will send a redirect.
}
export async retrieveTokenImplicitAccess(args) {
  const { authorizationEndpoint, tokenEndpoint } = args;
  const strAuthorizationEndpoint = coerseToString(authorizationEndpoint);
  const strTokenEndpoint = coerseToString(tokenEndpoint);
  // 
  const nonce = base64UrlEncode(strRaw32Random()).slice(0, -1);
  const params = new self.URLSearchParams([
    [ "client_id", this.#clientId ],
    [ "redirect_uri", redirectEndpoint ],
    [ "response_type", "token" ],
    [ "state", nonce ],
  ]);
  const authorizeURL = new self.URL(strAuthorizationEndpoint + "?" + params);
  window.sessionStorage.setItem("OAuth2", {
    grantType: "Implicit Grant",
    tokenEndpoint: strTokenEndpoint,
    state: nonce,
  });
  window.location = authorizeURL;
}

export class TokenManagement {
  // Below is the "Client Identifier" referred to in Section 2.2 of RFC6749. This is also referred to by some as the "App Id".
  // All methods in the library require the client identifier and therefore assume the client is registered. Unregistered clients per Section 2.4 of RFC6749 are not supported.
  // Type: string
  #clientId;
  // Below is the "Token Endpoint" per Section 3 of RFC6749. Section 3.2 of RFC6749 provides details.
  #tokenEndpoint;

  #accessToken;
  #refreshToken;
  #tokenType;
  #expiryDate;
  #callbackAccessToken;
  #callbackRefreshToken;
  constructor(args) {
    const { clientId, tokenEndpoint, accessToken, refreshToken, tokenType, expiryDate } = args;
    this.#clientId = clientId;
    if (typeof tokenEndpoint === "object" && tokenEndpoint !== null) {
      this.#tokenEndpoint = tokenEndpoint.toString();
    } else if (typeof tokenEndpoint === "string") {
      this.#tokenEndpoint = tokenEndpoint;
    } else {
      throw "tokenEndpoint must be a string";
    }
    this.#accessToken = accessToken;
    this.#refreshToken = refreshToken;
    this.#tokenType = tokenType;
    this.#expiryDate = expiryDate;
  }
  setTokens(args) {
    const { accessToken, refreshToken, tokenType, expiryDate } = args;
    this.#accessToken = accessToken;
    this.#refreshToken = refreshToken;
    this.#tokenType = tokenType;
    this.#expiryDate = expiryDate;
    if (typeof this.#callbackAccessToken === "function") {
      this.#callbackAccessToken(this.#accessToken);
    }
    if (typeof this.#callbackAccessToken === "function") {
      this.#callbackRefreshToken(this.#refreshToken);
    }
  }
  setCallbackAccessToken(callback) {
    this.#callbackAccessToken = callback;
  }
  setCallbackRefreshToken(callback) {
    this.#callbackRefreshToken = callback;
  }
  getAccessToken() {
    return this.#accessToken;
  }
  getRefreshToken() {
    return this.#refreshToken;
  }
  getTokenEndpoint() {
    return this.#tokenEndpoint;
  }
  async refreshAccessTokenPKCE() {
    const params = new self.URLSearchParams([
      ["grant_type", "refresh_token" ],
      ["refresh_token", this.#currentRefreshToken ],
      ["client_id", this.#clientId ],
    ]);
    const reqBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
    const req = createRequestPOST(this.#tokenEndpoint, reqBody);
    const resp = await fetch(req);
    const jsonRespBody = await resp.text();
    const objResp = JSON.parse(jsonRespBody);
    if (objResp["refresh_token"]) {
      this.setTokens({
        accessToken: objResp["access_token"],
        refreshToken: objResp["refresh_token"],
      });
    } else {
      this.setTokens({
        accessToken: objResp["access_token"]),
        refreshToken: "",
      });
    }
  }
  #revokeEndpoint;
  setRevokeEndpoint(newRevokeEndpoint) {
    this.#revokeEndpoint = newRevokeEndpoint;
  }
  getRevokeEndpoint() {
    return this.#revokeEndpoint;
  }
  async revokeToken(strToken) {
    const headers = [ [ "Authorization", "Bearer " + strToken ] ];
    const req = createRequestPOST(revokeEndpoint, null, headers);
    const resp = await fetch(req);
    console.log(resp);
    if (resp.status === 200) {
      console.log("Token Revoked");
      this.#accessToken = undefined;
      this.#refreshToken = undefined;
      this.#tokenType = undefined;
      this.#expiryDate = undefined;
    } else {
      console.log("Token Not Revoked");
    }
  }
  async fetch(request) {
    if ((new Date()) > this.#expiryDate) {
      await this.refreshAccessTokenPKCE();
    }
    let req = request.clone();
    req.headers.add([ "Authorization", this.#tokenType + " " + this.#accessToken ]);
    const resp = await fetch(req);
    return resp;
  }
}

const objOAuth2 = window.sessionStorage.getItem("OAuth2");
window.sessionStorage.removeItem("OAuth2");
export function isRedirect() {
  return !!objOAuth2;
}

export const receivedTokens = new Promise(function (resolve, reject) {
  if (isRedirect()) {
    switch (objOAuth2.grantType) {
      case "PKCE Access": {
        console.log("PKCE flow redirect callback - access token");
        redirectPKCEAccess().then(resolve).catch(reject);
      }
        break;
      case "PKCE Refresh": {
        console.log("PKCE flow redirect callback - refresh token");
        redirectPKCERefresh().then(resolve).catch(reject);
      }
        break;
      case "Implicit Access": {
        console.log("Implicit flow redirect callback - access token");
        redirectImplicitAccess().then(resolve).catch(reject);
      }
        break;
      // Implicit flow redirect callback - refresh token - NOT POSSIBLE
      default: {
        console.error("Invalid Authorization mode.");
      }
    };
  }
  window.history.replaceState(null, "", redirectEndpoint);
});
async function redirectPKCEAccess() {
  if (!(selfURLParams.has("code"))) {
    throw "code parameter required";
  }
  const authorizationCode = selfURLParams.get("code");
  if (!(selfURLParams.has("state"))) {
    throw "state parameter required";
  }
  const stateReceived = selfURLParams.get("state");
  const { codeVerifier, tokenEndpoint, state } = objOAuth2;
  if (stateReceived !== state) {
    throw "state does not match";
  }
  // Step (C) of Section 1.1 of RFC7636
  const params = new self.URLSearchParams([
    ["code", authorizationCode ],
    ["grant_type", "authorization_code" ],
    ["redirect_uri", redirectEndpoint ],
    ["code_verifier", codeVerifier ],
    ["client_id", this.#clientId ],
  ]);
  const reqBody = new self.Blob([ params.toString() ], { type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST(tokenEndpoint, reqBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  // Step (D) of Section 1.1 of RFC7636
  const objResp = JSON.parse(jsonRespBody);
  return {
    tokenEndpoint: tokenEndpoint,
    accessToken: objResp["access_token"],
    tokenType: objResp["token_type"],
    expiryDate: new Date(Date.now() + 1000 * objResp["expires_in"]),
  };
}
async function redirectPKCERefresh() {
  if (!(selfURLParams.has("code"))) {
    throw "code parameter required";
  }
  const authorizationCode = selfURLParams.get("code");
  if (!(selfURLParams.has("state"))) {
    throw "state parameter required";
  }
  const stateReceived = selfURLParams.get("state");
  const { codeVerifier, tokenEndpoint, state } = objOAuth2;
  if (stateReceived !== state) {
    throw "state does not match";
  }
  const params = new self.URLSearchParams([
    ["code", authorizationCode ],
    ["grant_type", "authorization_code" ],
    ["redirect_uri", redirectEndpoint ],
    ["code_verifier", codeVerifier ],
    ["client_id", this.#clientId ],
  ]);
  const reqBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST(tokenEndpoint, reqBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  const objResp = JSON.parse(jsonRespBody);
  return {
    tokenEndpoint: tokenEndpoint,
    accessToken: objResp["access_token"],
    refreshToken: objResp["refresh_token"],
    type: objResp["token_type"],
    expiryDate: new Date(Date.now() + 1000 * objResp["expires_in"]),
  };
}
async function redirectImplicitAccess() {
  const { codeVerifier, tokenEndpoint } = objOAuth2;
  const selfURLParamsFragment = new self.URLSearchParams(selfURLFragment);
  if (!(selfURLParamsFragment.has("access_token"))) {
    throw "access_token parameter required";
    break;
  }
  return {
    tokenEndpoint: tokenEndpoint,
    accessToken: selfURLParamsFragment.get("access_token"),
    tokenType: objResp["token_type"],
    expiryDate: new Date(Date.now() + 1000 * objResp["expires_in"]),
  };
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

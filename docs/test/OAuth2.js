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

export class TokenManagement {
  // Below is the "Client Identifier" referred to in Section 2.2 of RFC6749. This is also referred to by some as the "App Id".
  // All methods in the library require the client identifier and therefore assume the client is registered. Unregistered clients per Section 2.4 of RFC6749 are not supported.
  // Type: string
  #clientId;
  // Below is the "Authorization Endpoint" per Section 3 of RFC6749. Section 3.1 of RFC6749 provides details.
  // Type: URL
  #authorizationEndpoint;
  // Below is the "Token Endpoint" per Section 3 of RFC6749. Section 3.2 of RFC6749 provides details.
  // Type: URL
  #tokenEndpoint;

  #tokenType;
  #currentAccessToken;
  #currentRefreshToken;
  #callbackAccessToken;
  #callbackRefreshToken;
  constructor(args) {
    const { clientId, authorizationEndpoint, tokenEndpoint, accessToken, refreshToken, tokenType, expiryDate } = args;
    this.#clientId = clientId;
    this.#authorizationEndpoint = authorizationEndpoint;
    this.#tokenEndpoint = tokenEndpoint;
    this.#currentAccessToken = "";
    this.#currentRefreshToken = "";
  }
  setTokens(args) {
    const { tokenType, accessToken, refreshToken, expiresIn } = args;
    this.#expiresIn = expiresIn;
    this.#tokenType = tokenType;
    this.#currentAccessToken = accessToken;
    this.#currentRefreshToken = refreshToken;
    if (typeof this.#callbackAccessToken === "function") {
      this.#callbackAccessToken(currentAccessToken);
    }
    if (typeof this.#callbackAccessToken === "function") {
      this.#callbackRefreshToken(currentRefreshToken);
    }
  }
  checkForExpiredTokens() {
    for (const tokenSet of this.#tokens.values()) {
      for (const accessToken of tokenSet.accessTokens.values()) {
        if (Date.now() >= accessToken.expiryDate) {
          // delete access token
          tokenSet.accessTokens.delete(accessToken);
        }
      }
    }
  }
  setCallbackAccessToken(callback) {
    this.#callbackAccessToken = callback;
  }
  setCallbackRefreshToken(callback) {
    this.#callbackRefreshToken = callback;
  }
  getAccessToken() {
    return this.#currentAccessToken;
  }
  getRefreshToken() {
    return this.#currentRefreshToken;
  }
  // Note: This function will cause the page to refresh.
  async getPKCEAccessToken() {
    // Step (A) of Section 1.1 of RFC7636
    const nonceString = base64UrlEncode(strRaw32Random()).slice(0, -1);
    const codeVerifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
    const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(codeVerifier));
    const codeChallenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
    const params = new URLSearchParams([
      [ "client_id", this.#clientId ],
      [ "redirect_uri", redirectEndpoint ],
      [ "response_type", "code" ],
      [ "code_challenge", codeChallenge ],
      [ "code_challenge_method", "S256" ],
      [ "state", nonceString ],
    ]);
    const authorizeURL = new URL(this.#authorizationEndpoint + "?" + params);
    window.sessionStorage.setItem("OAuth2", {
      grant_type: "PKCE Access",
      code_verifier: codeVerifier,
    });
    window.location = authorizeURL;
    // Step (B) of Section 1.1 of RFC7636 occurs on the server. It will send a redirect.
  }
  // Note: This function will cause the page to refresh.
  async getPKCERefreshToken() {
    // Step (A) of Section 1.1 of RFC7636
    const nonceString = base64UrlEncode(strRaw32Random()).slice(0, -1);
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
      [ "state", nonceString ],
    ]);
    const authorizeURL = new URL(this.#authorizationEndpoint + "?" + params);
    window.sessionStorage.setItem("OAuth2", {
      grant_type: "PKCE Refresh",
      code_verifier: code_verifier,
    });
    window.location = authorizeURL;
    // Step (B) of Section 1.1 of RFC7636 occurs on the server. It will send a redirect.
  }
  // Note: This function will cause the page to refresh.
  async getImplicitAccessToken() {
    // 
    const nonceString = base64UrlEncode(strRaw32Random()).slice(0, -1);
    const params = new self.URLSearchParams([
      [ "client_id", this.#clientId ],
      [ "redirect_uri", redirectEndpoint ],
      [ "response_type", "token" ],
      [ "state", nonceString ],
    ]);
    const authorizeURL = new self.URL(this.#authorizationEndpoint + "?" + params);
    window.sessionStorage.setItem("OAuth2", {
      "grant_type": "Implicit Grant",
      "state": nonceString,
    });
    window.location = authorizeURL;
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
    console.log(objResp);
    if (objResp["refresh_token"]) {
      this.setCurrentTokenPair(objResp["refresh_token"], objResp["access_token"]);
    } else {
      this.setCurrentTokenPair("", objResp["access_token"]);
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
      this.#setAccessToken("");
      this.#setRefreshToken("");
    } else {
      console.log("Token Not Revoked");
    }
  }
  async fetch(request) {
    this.purgeExpiredTokens();
    if (this.#currentAccessToken === "") {
      await this.refreshAccessTokenPKCE();
    }
    let req = request.clone();
    req.headers.add([ "Authorization", this.#currentTokenType + " " + this.#currentAccessToken ]);
    const resp = await fetch(req);
    return resp;
  }
}

const objOAuth2 = window.sessionStorage.getItem("OAuth2");
window.sessionStorage.removeItem("OAuth2");
export function isRedirect() {
  return !!objOAuth2;
}

export const receivedTokenPair = new Promise(function (resolve, reject) {
  if (isRedirect()) {
    switch (objOAuth2["grantType"]) {
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
  if (!(selfURLParams.has("state"))) {
    throw "state parameter required";
  }
  const stateReceived = selfURLParams.get("state");
  const stateSaved = objOAuth2["state"];
  if (stateReceived !== stateSaved) {
    throw "state does not match";
  }
  const authorizationCode = selfURLParams.get("code");
  const codeVerifier = objOAuth2["code_verifier"];
  // Step (C) of Section 1.1 of RFC7636
  const params = new self.URLSearchParams([
    ["code", authorizationCode ],
    ["grant_type", "authorization_code" ],
    ["redirect_uri", redirectEndpoint ],
    ["code_verifier", codeVerifier ],
    ["client_id", this.#clientId ],
  ]);
  const reqBody = new self.Blob([ params.toString() ], { type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST(objOAuth2["token_endpoint"], reqBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  // Step (D) of Section 1.1 of RFC7636
  const objResp = JSON.parse(jsonRespBody);
  return {
    token: objResp["access_token"],
    type: objResp["token_type"],
    expiry_date: new Date(Date.now() + 1000 * objResp["expires_in"]),
  };
}
async function redirectPKCERefresh() {
  if (!(selfURLParams.has("code"))) {
    reject();
    break;
  }
  if (!(selfURLParams.has("state"))) {
    reject();
    break;
  }
  const stateReceived = selfURLParams.get("state");
  const stateSaved = objOAuth2["state"];
  if (stateReceived !== stateSaved) {
    throw "state does not match";
  }
  const authorizationCode = selfURLParams.get("code");
  const codeVerifier = objOAuth2["code_verifier"];
  const params = new self.URLSearchParams([
    ["code", authorizationCode ],
    ["grant_type", "authorization_code" ],
    ["redirect_uri", redirectEndpoint ],
    ["code_verifier", codeVerifier ],
    ["client_id", this.#clientId ],
  ]);
  const reqBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST(objOAuth2["token_endpoint"], reqBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  const objResp = JSON.parse(jsonRespBody);
  return {
    access_token: objResp["access_token"],
    refresh_token: objResp["refresh_token"],
    type: objResp["token_type"],
    expiry_date: new Date(Date.now() + 1000 * objResp["expires_in"]),
  };
}
async function redirectImplicitAccess() {
  const selfURLParamsFragment = new self.URLSearchParams(selfURLFragment);
  if (!(selfURLParamsFragment.has("access_token"))) {
    throw "access_token parameter required";
    break;
  }
  return {
    access_token: selfURLParamsFragment.get("access_token"),
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

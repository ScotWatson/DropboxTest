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
  // Below is the name of the associated API. This is used to identify which API is token is for on a redirect.
  #nameAPI;

  #tokenType;
  #currentAccessToken;
  #currentRefreshToken;
  #callbackAccessToken;
  #callbackRefreshToken;
  constructor(args) {
    const { clientId, authorizationEndpoint, tokenEndpoint, nameAPI } = args;
    this.#clientId = clientId;
    this.#authorizationEndpoint = authorizationEndpoint;
    this.#tokenEndpoint = tokenEndpoint;
    this.#nameAPI = nameAPI;
    this.#currentAccessToken = "";
    this.#currentRefreshToken = "";
  }
  setTokens(tokenType, accessToken, refreshToken, expiresIn) {
    this.#tokenType = tokenType;
    this.#tokenType = tokenType;
    this.#currentAccessToken = accessToken;
    this.#currentRefreshToken = refreshToken;
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
  setAccessToken(strToken) {
    this.#currentAccessToken = strToken;
    if (typeof this.#callbackAccessToken === "function") {
      this.#callbackAccessToken(currentAccessToken);
    }
  }
  setRefreshToken(strToken) {
    this.#currentRefreshToken = strToken;
    if (typeof this.#callbackAccessToken === "function") {
      this.#callbackRefreshToken(currentRefreshToken);
    }
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
    const code_verifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
    const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
    const code_challenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
    const params = new URLSearchParams([
      [ "client_id", this.#clientId ],
      [ "redirect_uri", redirectEndpoint ],
      [ "response_type", "code" ],
      [ "code_challenge", code_challenge ],
      [ "code_challenge_method", "S256" ],
      [ "state", nonceString ],
    ]);
    const authorizeURL = new URL(this.#authorizationEndpoint + "?" + params);
    window.sessionStorage.setItem("OAuth2", {
      nameAPI: this.#nameAPI,
      auth_mode: "PKCE Access",
      code_verifier: code_verifier,
    });
    window.location = authorizeURL;
    // Step (B) of Section 1.1 of RFC7636 occurs on the server. It will send a redirect.
  }
  // Note: This function will cause the page to refresh.
  async getPKCERefreshToken() {
    // Step (A) of Section 1.1 of RFC7636
    const nonceString = base64UrlEncode(strRaw32Random()).slice(0, -1);
    const code_verifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
    const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
    const code_challenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
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
      nameAPI: this.#nameAPI,
      auth_mode: "PKCE Refresh",
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
      "name_API": this.#nameAPI,
      "auth_mode": "Implicit Grant",
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
    const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
    const req = createRequestPOST(this.#tokenEndpoint, blobBody);
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
    
    let req = request.clone();
    req.headers.add([ "Authorization", "Bearer " + strToken ]);
    const resp = await fetch(req);
    return resp;
  }
}
parseRedirectParameters();

function parseRedirectParameters() {
  const objOAuth2 = window.sessionStorage.getItem("OAuth2");
  if (objOAuth2) {
    switch (objOAuth2["auth_mode"]) {
      case "PKCE Access": {
        // PKCE flow redirect callback - access token
        if (selfURLParams.has("code")) {
          console.log("PKCE flow redirect callback - access token");
          const authorization_code = selfURLParams.get("code");
          const code_verifier = objOAuth2["code_verifier"];
          (async function () {
            // Step (C) of Section 1.1 of RFC7636
            const params = new self.URLSearchParams([
              ["code", authorization_code ],
              ["grant_type", "authorization_code" ],
              ["redirect_uri", redirectEndpoint ],
              ["code_verifier", code_verifier ],
              ["client_id", this.#clientId ],
            ]);
            const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
            const req = createRequestPOST(objOAuth2.tokenEndpoint, blobBody);
            const resp = await fetch(req);
            const jsonRespBody = await resp.text();
            // Step (D) of Section 1.1 of RFC7636
            const objResp = JSON.parse(jsonRespBody);
            console.log(objResp);
            setAccessToken();
            this.#objRefreshToken.arrAccessTokens.push({
              token: objResp["access_token"],
              type: objResp["token_type"],
              expiry_date: new Date(Date.now() + 1000 * objResp["expires_in"]),
            });
            this.#tokens = [];
            this.#tokens.push({
              refresh_token: objResp["refresh_token"],
              refresh_token_type: objResp["token_type"],
              access_tokens: [
                {
                  token: objResp["access_token"],
                  type: objResp["access_token"],
                  expiry_date: new Date(),
                },
              ],
            });
          })();
          window.sessionStorage.removeItem("auth_mode");
          window.sessionStorage.removeItem("code_verifier");
          window.history.replaceState(null, "", redirectEndpoint);
        }
      }
        break;
      case "PKCE Refresh": {
        // PKCE flow redirect callback - refresh token
        if (selfURLParams.has("code")) {
          console.log("PKCE flow redirect callback - refresh token");
          const authorization_code = selfURLParams.get("code");
          const code_verifier = window.sessionStorage.getItem("code_verifier");
          (async function () {
            const params = new self.URLSearchParams([
              ["code", authorization_code ],
              ["grant_type", "authorization_code" ],
              ["redirect_uri", redirectEndpoint ],
              ["code_verifier", code_verifier ],
              ["client_id", this.#clientId ],
            ]);
            const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
            const req = createRequestPOST(this.#tokenEndpoint, blobBody);
            const resp = await fetch(req);
            const jsonRespBody = await resp.text();
            const objResp = JSON.parse(jsonRespBody);
            console.log(objResp);
            setAccessToken(objResp["access_token"]);
            setRefreshToken(objResp["refresh_token"]);
          })();
          window.sessionStorage.removeItem("auth_mode");
          window.sessionStorage.removeItem("code_verifier");
          window.history.replaceState(null, "", redirectEndpoint);
        }
      }
        break;
      case "Implicit Access": {
        const selfURLParamsFragment = new self.URLSearchParams(selfURLFragment);
        if (selfURLParamsFragment.get("access_token")) {
          // Implicit flow redirect callback - access token
          console.log("Implicit flow redirect callback - access token");
          setAccessToken(selfURLParamsFragment.get("access_token"));
          window.sessionStorage.removeItem("auth_mode");
          window.history.replaceState(null, "", redirectEndpoint);
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

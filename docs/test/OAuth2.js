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

// Below is the "Redirect Endpoint" per Section 3 of RFC 6749. Section 3.1.2 of RFC 6749 provides details. It is taken to be the current location.
const urlRedirectEndpoint = new self.URL(urlThis.origin + urlThis.pathname);

export {
  // Below is the "Client Identifier" referred to in Section 2.2 of RFC 6749. This is also referred to by some as the "App Id".
  // All methods in the library require the client identifier and therefore assume the client is registered. Unregistered clients per Section 2.4 of RFC 6749 are not supported.
  #strClientId;
  // Below is the "Authorization Endpoint" per Section 3 of RFC 6749. Section 3.1 of RFC 6749 provides details.
  #urlAuthorizationEndpoint;
  // Below is the "Token Endpoint" per Section 3 of RFC 6749. Section 3.2 of RFC 6749 provides details.
  #urlTokenEndpoint;

  #strAccessToken = "";
  #strRefreshToken = "";
  #callbackAccessToken;
  #callbackRefreshToken;
  constructor(args) {
    ({ strClientId, urlAuthorizationEndpoint, urlTokenEndpoint } = args);
  }
  setCallbackAccessToken(callback) {
    this.#callbackAccessToken = callback;
  }
  setCallbackRefreshToken(callback) {
    this.#callbackRefreshToken = callback;
  }
  setAccessToken(strToken) {
    this.#strAccessToken = strToken;
    if (typeof this.#callbackAccessToken === "function") {
      this.#callbackAccessToken(strAccessToken);
    }
  }
  setRefreshToken(strToken) {
    this.#strRefreshToken = strToken;
    if (typeof this.#callbackAccessToken === "function") {
      this.#callbackRefreshToken(strRefreshToken);
    }
  }
  getAccessToken() {
    return this.#strAccessToken;
  }
  getRefreshToken() {
    return this.#strRefreshToken;
  }
  async getPKCEAccessToken() {
    // Step (A) of Section 1.1 of RFC7636
    const code_verifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
    const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
    const code_challenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
    window.sessionStorage.setItem("code_verifier", code_verifier);
    const params = new URLSearchParams([
      [ "client_id", this.#strClientId ],
      [ "redirect_uri", urlRedirectEndpoint ],
      [ "response_type", "code" ],
      [ "code_challenge", code_challenge ],
      [ "code_challenge_method", "S256" ],
    ]);
    const urlAuthorize = new URL(this.#urlAuthorizationEndpoint + "?" + params);
    window.sessionStorage.setItem("auth_mode", "PKCE Access");
    window.location = urlAuthorize;
    // Step (B) of Section 1.1 of RFC7636 occurs on the server. It will send a redirect.
  }
  async getPKCERefreshToken() {
    // Step (A) of Section 1.1 of RFC7636
    const code_verifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
    const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
    const code_challenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
    window.sessionStorage.setItem("code_verifier", code_verifier);
    const params = new URLSearchParams([
      [ "client_id", this.#strClientId ],
      [ "redirect_uri", urlRedirectEndpoint ],
      [ "token_access_type", "offline" ],
      [ "response_type", "code" ],
      [ "code_challenge", code_challenge ],
      [ "code_challenge_method", "S256" ],
    ]);
    const urlAuthorize = new URL(this.#urlAuthorizationEndpoint + "?" + params);
    window.sessionStorage.setItem("auth_mode", "PKCE Refresh");
    window.location = urlAuthorize;
    // Step (B) of Section 1.1 of RFC7636 occurs on the server. It will send a redirect.
  }
  async getImplicitAccessToken() {
    const params = new URLSearchParams([
      [ "client_id", this.#strClientId ],
      [ "redirect_uri", urlRedirectEndpoint ],
      [ "response_type", "token" ],
    ]);
    const urlAuthorize = new URL(this.#urlAuthorizationEndpoint + "?" + params);
    window.sessionStorage.setItem("auth_mode", "Implicit Access");
    window.location = urlAuthorize;
  }
  parseRedirectParameters() {
    const auth_mode = window.sessionStorage.getItem("auth_mode");
    if (auth_mode) {
      switch (auth_mode) {
        case "PKCE Access": {
          // PKCE flow redirect callback - access token
          if (paramsThis.has("code")) {
            console.log("PKCE flow redirect callback - access token");
            const authorization_code = paramsThis.get("code");
            const code_verifier = window.sessionStorage.getItem("code_verifier");
            (async function () {
              // Step (C) of Section 1.1 of RFC7636
              const params = new self.URLSearchParams([
                ["code", authorization_code ],
                ["grant_type", "authorization_code" ],
                ["redirect_uri", urlRedirectEndpoint ],
                ["code_verifier", code_verifier ],
                ["client_id", this.#strClientId ],
              ]);
              const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
              const req = createRequestPOST(urlTokenEndpoint, blobBody);
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
            window.history.replaceState(null, "", urlRedirectEndpoint);
          }
        }
          break;
        case "PKCE Refresh": {
          // PKCE flow redirect callback - refresh token
          if (paramsThis.has("code")) {
            console.log("PKCE flow redirect callback - refresh token");
            const authorization_code = paramsThis.get("code");
            const code_verifier = window.sessionStorage.getItem("code_verifier");
            (async function () {
              const params = new self.URLSearchParams([
                ["code", authorization_code ],
                ["grant_type", "authorization_code" ],
                ["redirect_uri", urlRedirectEndpoint ],
                ["code_verifier", code_verifier ],
                ["client_id", this.#strClientId ],
              ]);
              const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
              const req = createRequestPOST(this.#urlTokenEndpoint, blobBody);
              const resp = await fetch(req);
              const jsonRespBody = await resp.text();
              const objResp = JSON.parse(jsonRespBody);
              console.log(objResp);
              setAccessToken(objResp["access_token"]);
              setRefreshToken(objResp["refresh_token"]);
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
            console.log("Implicit flow redirect callback - access token");
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
  async tokenAccessFromRefreshPKCE() {
    const params = new self.URLSearchParams([
      ["grant_type", "refresh_token" ],
      ["refresh_token", this.#strRefreshToken ],
      ["client_id", this.#strClientId ],
    ]);
    const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
    const req = createRequestPOST(this.#urlTokenEndpoint, blobBody);
    const resp = await fetch(req);
    const jsonRespBody = await resp.text();
    const objResp = JSON.parse(jsonRespBody);
    console.log(objResp);
    return objResp["access_token"];
  }
  #urlRevokeEndpoint;
  setRevokeEndpoint(urlNewRevokeEndpoint) {
    this.#urlRevokeEndpoint = urlNewRevokeEndpoint;
  }
  getRevokeEndpoint() {
    return this.#urlRevokeEndpoint;
  }
  async revokeToken(strToken) {
    const headers = [ [ "Authorization", "Bearer " + strToken ] ];
    const reqRevokeToken = createRequestPOST(urlRevokeEndpoint, null, headers);
    const respRevokeToken = await fetch(reqRevokeToken);
    console.log(respRevokeToken);
    if (respRevokeToken.status === 200) {
      console.log("Token Revoked");
      this.#setAccessToken("");
      this.#setRefreshToken("");
    } else {
      console.log("Token Not Revoked");
    }
  }
  async fetch(request) {
    let req = request.clone();
    req.headers.add([ "Authorization", "Bearer " + strToken ]);
    const resp = await fetch(req);
    return resp;
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

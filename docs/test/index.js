/*
(c) 2024 Scot Watson  All Rights Reserved
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

const initPageTime = performance.now();

const asyncWindow = new Promise(function (resolve, reject) {
  window.addEventListener("load", function (evt) {
    resolve(evt);
  });
});

(async function () {
  try {
    const modules = await Promise.all( [ asyncWindow ] );
    start(modules);
  } catch (e) {
    console.error(e);
    throw e;
  }
})();

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

const strAppId = "m1po2j6iw2k75n4";
const urlThis = new self.URL(window.location);
const paramsThis = urlThis.searchParams;
const urlRedirect = urlThis.origin + urlThis.pathname;
const strThisFragment = urlThis.hash.substring(1);
let strAccessToken = "";
let strRefreshToken = "";

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
          strAccessToken = await tokenAccessPKCE(authorization_code, urlRedirect, code_verifier, strAppId);
        })();
        window.sessionStorage.removeItem("auth_mode");
        window.sessionStorage.removeItem("code_verifier");
      }
    }
      break;
    case "PKCE Refresh": {
      // PKCE flow redirect callback - refresh token
      if (paramsThis.has("code")) {
        alert("PKCE flow redirect callback - refresh token");
        const refresh_token = paramsThis.get("code");
        (async function () {
          strRefreshToken = await tokenRefreshPKCE(refresh_token, strAppId);
        })();
        window.sessionStorage.removeItem("auth_mode");
      }
    }
      break;
    case "Implicit Access": {
      const paramsThisFragment = new self.URLSearchParams(strThisFragment);
      if (paramsThisFragment.get("access_token")) {
        // Implicit flow redirect callback - access token
        alert("Implicit flow redirect callback - access token");
        strAccessToken = paramsThisFragment.get("access_token");
        window.sessionStorage.removeItem("auth_mode");
      }
    }
      break;
    // Implicit flow redirect callback - refresh token - NOT POSSIBLE
    default: {
      console.error("Invalid Authorization mode.");
    }
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
async function tokenAccessPKCE(authorization_code, redirect_uri, verification_code, app_key) {
  const params = new self.URLSearchParams([
    ["code", authorization_code ],
    ["grant_type", "authorization_code" ],
    ["redirect_uri", redirect_uri ],
    ["code_verifier", verification_code ],
    ["client_id", app_key ],
  ]);
  const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST("https://api.dropboxapi.com/oauth2/token", blobBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  const objResp = JSON.parse(jsonRespBody);
  return objResp["access_token"];
}
async function tokenRefreshPKCE(refresh_token, app_key) {
  const params = new self.URLSearchParams([
    ["grant_type", "refresh_token" ],
    ["refresh_token", verification_code ],
    ["client_id", app_key ],
  ]);
  const blobBody = new self.Blob([ params.toString() ], {type: "application/x-www-form-urlencoded" });
  const req = createRequestPOST("https://api.dropboxapi.com/oauth2/token", blobBody);
  const resp = await fetch(req);
  const jsonRespBody = await resp.text();
  const objResp = JSON.parse(jsonRespBody);
  console.log(objResp);
  return objResp["access_token"];
}

function start([ evtWindow ]) {
  try {
    const pAccessToken = document.createElement("p");
    const btnSetAccessToken = document.createElement("button");
    btnSetAccessToken.innerHTML = "Set Token";
    btnSetAccessToken.addEventListener("click", function (evt) {
      strNewToken = window.prompt("Enter the access token: ");
      if (strNewToken) {
        setAccessToken(strNewToken);
      }
    });
    pAccessToken.appendChild(btnSetAccessToken);
    const btnGetImplicitAccessToken = document.createElement("button");
    btnGetImplicitAccessToken.innerHTML = "Get Implicit Access Token";
    btnGetImplicitAccessToken.addEventListener("click", function (evt) {
      (async function () {
        const params = new URLSearchParams([
          [ "client_id", strAppId ],
          [ "redirect_uri", urlRedirect ],
          [ "response_type", "token" ],
        ]);
        const urlAuthorize = new URL("https://www.dropbox.com/oauth2/authorize?" + params);
        window.sessionStorage.setItem("auth_mode", "Implicit Access");
        window.location = urlAuthorize;
      })();
    });
    pAccessToken.appendChild(btnGetImplicitAccessToken);
    const btnGetPKCEAccessToken = document.createElement("button");
    btnGetPKCEAccessToken.innerHTML = "Get PKCE Access Token";
    btnGetPKCEAccessToken.addEventListener("click", function (evt) {
      (async function () {
        const code_verifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
        const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
        const code_challenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
        window.sessionStorage.setItem("code_verifier", code_verifier);
        const params = new URLSearchParams([
          [ "client_id", strAppId ],
          [ "redirect_uri", urlRedirect ],
          [ "response_type", "code" ],
          [ "code_challenge", code_challenge ],
          [ "code_challenge_method", "S256" ],
        ]);
        const urlAuthorize = new URL("https://www.dropbox.com/oauth2/authorize?" + params);
        window.sessionStorage.setItem("auth_mode", "PKCE Access");
        window.location = urlAuthorize;
      })();
    });
    pAccessToken.appendChild(btnGetPKCEAccessToken);
    const btnRevokeAccessToken = document.createElement("button");
    btnRevokeAccessToken.innerHTML = "Revoke Access Token";
    btnRevokeAccessToken.addEventListener("click", function (evt) {
      revokeToken(strAccessToken);
      setAccessToken("");
    });
    pAccessToken.appendChild(btnRevokeAccessToken);
    const spanAccessToken = document.createElement("span");
    spanAccessToken.append(strAccessToken);
    pAccessToken.appendChild(spanAccessToken);
    function setAccessToken(token) {
      strAccessToken = token;
      spanAccessToken.innerHTML = "";
      spanAccessToken.append(strAccessToken);
    }
    document.body.appendChild(pAccessToken);

    const pRefreshToken = document.createElement("p");
    const btnSetRefreshToken = document.createElement("button");
    btnSetRefreshToken.innerHTML = "Set Token";
    btnSetRefreshToken.addEventListener("click", function (evt) {
      strNewToken = window.prompt("Enter the refresh token: ");
      if (strNewToken) {
        setRefreshToken(strNewToken);
      }
    });
    pRefreshToken.appendChild(btnSetRefreshToken);
    const btnGetPKCERefreshToken = document.createElement("button");
    btnGetPKCERefreshToken.innerHTML = "Get PKCE Refresh Token";
    btnGetPKCERefreshToken.addEventListener("click", function (evt) {
      (async function () {
        const code_verifier = base64UrlEncode(strRaw32Random()).slice(0, -1);
        const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
        const code_challenge = base64UrlEncode(rawFromBytes(bytesHash)).slice(0, -1);
        window.sessionStorage.setItem("code_verifier", code_verifier);
        const params = new URLSearchParams([
          [ "client_id", strAppId ],
          [ "redirect_uri", urlRedirect ],
          [ "token_access_type", "offline" ],
          [ "response_type", "code" ],
          [ "code_challenge", code_challenge ],
          [ "code_challenge_method", "S256" ],
        ]);
        const urlAuthorize = new URL("https://www.dropbox.com/oauth2/authorize?" + params);
        window.sessionStorage.setItem("auth_mode", "PKCE Refresh");
        window.location = urlAuthorize;
      })();
    });
    pRefreshToken.appendChild(btnGetPKCERefreshToken);
    const btnRevokeRefreshToken = document.createElement("button");
    btnRevokeRefreshToken.innerHTML = "Revoke Refresh Token";
    btnRevokeRefreshToken.addEventListener("click", function (evt) {
      revokeToken(strRefreshToken);
      setRefreshToken("");
    });
    pRefreshToken.appendChild(btnRevokeRefreshToken);
    const spanRefreshToken = document.createElement("span");
    spanRefreshToken.append(strRefreshToken);
    pRefreshToken.appendChild(spanRefreshToken);
    function setRefreshToken(token) {
      strRefreshToken = token;
      spanRefreshToken.innerHTML = "";
      spanRefreshToken.append(strRefreshToken);
    }
    document.body.appendChild(pRefreshToken);

    const btnListFolder = document.createElement("button");
    btnListFolder.innerHTML = "List Folder";
    btnListFolder.addEventListener("click", function (evt) {
      list_folder();
    });
    document.body.appendChild(btnListFolder);
    const inpPath = document.createElement("input");
    inpPath.type = "text";
    document.body.appendChild(inpPath);
    const btnDownload = document.createElement("button");
    btnDownload.innerHTML = "Download";
    btnDownload.addEventListener("click", function (evt) {
      download(inpPath.value);
    });
    document.body.appendChild(btnDownload);
    async function list_folder() {
      const objReqBody = {
        include_deleted: false,
        include_has_explicit_shared_members: false,
        include_media_info: false,
        include_mounted_folders: true,
        include_non_downloadable_files: true,
        path: "",
        recursive: false,
      };
      const jsonReqBody = JSON.stringify(objReqBody);
      const blobReqBody = new Blob([ jsonReqBody ], { type: "application/json" });
      const headers = [ [ "Authorization", "Bearer " + strAccessToken ] ];
      const reqFileList = createRequestPOST("https://api.dropboxapi.com/2/files/list_folder", blobReqBody, headers);
      const respFileList = await fetch(reqFileList);
      if (respFileList.status === 200) {
        const jsonRespBody = await respFileList.text();
        const objRespBody = JSON.parse(jsonRespBody);
        console.log(objRespBody);
      }
    }
    async function download(path) {
      const objReqArg = {
        path: path,
      };
      const jsonReqArg = JSON.stringify(objReqArg);
      const headers = [ [ "Authorization", "Bearer " + strAccessToken ], [ "Dropbox-API-Arg",  jsonReqArg ] ];
      const reqDownload = createRequestPOST("https://content.dropboxapi.com/2/files/download", null, headers);
      const respDownload = await fetch(reqDownload);
      if (respDownload.status === 200) {
        const jsonResult = respDownload.headers.get("dropbox-api-result");
        const objRespBody = JSON.parse(jsonResult);
        console.log(objRespBody);
        const strRespBody = await respDownload.text();
        console.log(strRespBody);
      }
    }
    async function revokeToken(strToken) {
      const headers = [ [ "Authorization", "Bearer " + strToken ] ];
      const reqRevokeToken = createRequestPOST("https://api.dropboxapi.com/2/auth/token/revoke", null, headers);
      const respRevokeToken = await fetch(reqRevokeToken);
      console.log(respRevokeToken);
      if (respRevokeToken.status === 200) {
        console.log("Token Revoked");
      } else {
        console.log("Token Not Revoked");
      }
    }
  } catch (e) {
    console.error(e);
  }
}

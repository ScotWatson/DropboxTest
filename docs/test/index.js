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

const asyncOAuth2 = import("./OAuth2.js");

(async function () {
  try {
    const modules = await Promise.all( [ asyncWindow, asyncOAuth2 ] );
    start(modules);
  } catch (e) {
    console.error(e);
    throw e;
  }
})();

(async function () {
  const OAuth2 = await asyncOAuth2;
  strClientId = "m1po2j6iw2k75n4";
  OAuth2.urlAuthorizationEndpoint = new self.URL("https://www.dropbox.com/oauth2/authorize");
  OAuth2.urlTokenEndpoint = new self.URL("https://api.dropboxapi.com/oauth2/token");
  OAuth2.urlRevokeEndpoint = new URL("https://api.dropboxapi.com/2/auth/token/revoke");
  OAuth2.parseRedirectParameters();
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

const urlThis = new self.URL(window.location);
const paramsThis = urlThis.searchParams;
const strThisFragment = urlThis.hash.substring(1);

function start([ evtWindow, OAuth2 ]) {
  try {
    const btnRevokeTokens = document.createElement("button");
    btnRevokeTokens.innerHTML = "Revoke Tokens";
    btnRevokeTokens.addEventListener("click", function (evt) {
      OAuth2.revokeToken(OAuth2.getAccessToken());
    });
    document.body.appendChild(btnRevokeTokens);
    const pAccessToken = document.createElement("p");
    const btnSetAccessToken = document.createElement("button");
    btnSetAccessToken.innerHTML = "Set Access Token";
    btnSetAccessToken.addEventListener("click", function (evt) {
      strNewToken = window.prompt("Enter the access token: ");
      if (strNewToken) {
        OAuth2.setAccessToken(strNewToken);
      }
    });
    pAccessToken.appendChild(btnSetAccessToken);
    const btnGetImplicitAccessToken = document.createElement("button");
    btnGetImplicitAccessToken.innerHTML = "Get Implicit Access Token";
    btnGetImplicitAccessToken.addEventListener("click", function (evt) {
      OAuth2.getImplicitAccessToken();
    });
    pAccessToken.appendChild(btnGetImplicitAccessToken);
    const btnGetPKCEAccessToken = document.createElement("button");
    btnGetPKCEAccessToken.innerHTML = "Get PKCE Access Token";
    btnGetPKCEAccessToken.addEventListener("click", function (evt) {
      OAuth2.getPKCEAccessToken();
    });
    pAccessToken.appendChild(btnGetPKCEAccessToken);
    const spanAccessToken = document.createElement("span");
    spanAccessToken.append(OAuth2.getAccessToken());
    OAuth2.callbackAccessToken = function (strToken) {
      spanAccessToken.innerHTML = "";
      spanAccessToken.append(strToken);
    }
    pAccessToken.appendChild(spanAccessToken);
    document.body.appendChild(pAccessToken);

    const pRefreshToken = document.createElement("p");
    const btnSetRefreshToken = document.createElement("button");
    btnSetRefreshToken.innerHTML = "Set Refresh Token";
    btnSetRefreshToken.addEventListener("click", function (evt) {
      strNewToken = window.prompt("Enter the refresh token: ");
      if (strNewToken) {
        OAuth2.setRefreshToken(strNewToken);
      }
    });
    pRefreshToken.appendChild(btnSetRefreshToken);
    const btnGetPKCERefreshToken = document.createElement("button");
    btnGetPKCERefreshToken.innerHTML = "Get PKCE Refresh Token";
    btnGetPKCERefreshToken.addEventListener("click", function (evt) {
      OAuth2.getPKCERefreshToken();
    });
    pRefreshToken.appendChild(btnGetPKCERefreshToken);
    const btnCreateAccessToken = document.createElement("button");
    btnCreateAccessToken.innerHTML = "Create Access Token";
    btnCreateAccessToken.addEventListener("click", function (evt) {
      (async function () {
        OAuth2.setAccessToken(await OAuth2.tokenAccessFromRefreshPKCE());
      })();
    });
    pRefreshToken.appendChild(btnCreateAccessToken);
    const spanRefreshToken = document.createElement("span");
    spanRefreshToken.append(OAuth2.getRefreshToken());
    OAuth2.callbackRefreshToken = function (strToken) {
      spanRefreshToken.innerHTML = "";
      spanRefreshToken.append(strToken);
    }
    pRefreshToken.appendChild(spanRefreshToken);
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
      const headers = [ [ "Authorization", "Bearer " + OAuth2.getAccessToken() ] ];
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
      const headers = [ [ "Authorization", "Bearer " + OAuth2.getAccessToken() ], [ "Dropbox-API-Arg",  jsonReqArg ] ];
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
  } catch (e) {
    console.error(e);
  }
}

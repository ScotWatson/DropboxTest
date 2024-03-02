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

const asyncOAuth2 = import("https://scotwatson.github.io/OAuth2/20240302/OAuth2.js");

(async function () {
  try {
    const modules = await Promise.all( [ asyncWindow, asyncOAuth2 ] );
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

function start([ evtWindow, OAuth2 ]) {
  try {
    const selfURL = new self.URL(window.location);
    const selfURLParams = selfURL.searchParams;
    const selfURLFragment = selfURL.hash.substring(1);
    const fragmentParams = new URLSearchParams(selfURLFragment);
    const clientId = fragmentParams.get("appId");
    const dropboxAuthorizationEndpoint = new self.URL("https://www.dropbox.com/oauth2/authorize");
    const dropboxTokenEndpoint = new self.URL("https://api.dropboxapi.com/oauth2/token");
    if (clientId !== null) {
      createTokenManager({
        clientId: clientId,
        tokenEndpoint: dropboxTokenEndpoint,
      });
    }
    function createTokenManager(args) {
      const div = document.createElement("div");
      const pClientId = document.createElement("p");
      pClientId.append(args.clientId);
      div.appendChild(pClientId);
      const dropboxTokenManagement = new OAuth2.TokenManagement(args);
      async function revokeDropboxTokens() {
        const revokeEndpoint = new self.URL("https://api.dropboxapi.com/2/auth/token/revoke");
        const req = createRequestPOST(revokeEndpoint, null, []);
        const resp = await dropboxTokenManagement.fetch(req);
        console.log(resp);
        if (resp.status === 200) {
          console.log("Tokens Revoked");
          dropboxTokenManagement.setTokens({});
        } else {
          console.log("Tokens Not Revoked");
        }
      }
      const btnRevokeTokens = document.createElement("button");
      btnRevokeTokens.innerHTML = "Revoke Tokens";
      btnRevokeTokens.addEventListener("click", function (evt) {
        revokeDropboxTokens();
      });
      div.appendChild(btnRevokeTokens);
      const pAccessToken = document.createElement("p");
      const btnSetAccessToken = document.createElement("button");
      btnSetAccessToken.innerHTML = "Set Access Token";
      btnSetAccessToken.addEventListener("click", function (evt) {
        newAccessToken = window.prompt("Enter the access token: ");
        if (newAccessToken) {
          dropboxTokenManagement.setTokens({
            accessToken: newAccessToken,
            refreshToken: dropboxTokenManagement.getRefreshToken(),
            tokenType: dropboxTokenManagement.getTokenType(),
            expiryDate: new Date(Date.now + 14400 * 1000),
          });
        }
      });
      pAccessToken.appendChild(btnSetAccessToken);
      const btnGetImplicitAccessToken = document.createElement("button");
      btnGetImplicitAccessToken.innerHTML = "Get Implicit Access Token";
      btnGetImplicitAccessToken.addEventListener("click", function (evt) {
        console.log(OAuth2.url);
        dropboxTokenManagement.retrieveTokenImplicitAccess({
          authorizationEndpoint: dropboxAuthorizationEndpoint,
        });
      });
      pAccessToken.appendChild(btnGetImplicitAccessToken);
      const btnGetPKCEAccessToken = document.createElement("button");
      btnGetPKCEAccessToken.innerHTML = "Get PKCE Access Token";
      btnGetPKCEAccessToken.addEventListener("click", function (evt) {
        dropboxTokenManagement.retrieveTokenPKCEAccess({
          authorizationEndpoint: dropboxAuthorizationEndpoint,
        });
      });
      pAccessToken.appendChild(btnGetPKCEAccessToken);
      const spanAccessToken = document.createElement("span");
      spanAccessToken.append(dropboxTokenManagement.getAccessToken());
      dropboxTokenManagement.setCallbackAccessToken(function (strToken) {
        spanAccessToken.innerHTML = "";
        spanAccessToken.append(strToken);
      });
      pAccessToken.appendChild(spanAccessToken);
      div.appendChild(pAccessToken);
  
      const pRefreshToken = document.createElement("p");
      const btnSetRefreshToken = document.createElement("button");
      btnSetRefreshToken.innerHTML = "Set Refresh Token";
      btnSetRefreshToken.addEventListener("click", function (evt) {
        newRefreshToken = window.prompt("Enter the refresh token: ");
        if (newRefreshToken) {
          dropboxTokenManagement.setRefreshToken({
            accessToken: dropboxTokenManagement.getAccessToken(),
            refreshToken: newRefreshToken,
            tokenType: dropboxTokenManagement.getTokenType(),
            expiryDate: dropboxTokenManagement.getExpiryDate(),
          });
        }
      });
      pRefreshToken.appendChild(btnSetRefreshToken);
      const btnGetPKCERefreshToken = document.createElement("button");
      btnGetPKCERefreshToken.innerHTML = "Get PKCE Refresh Token";
      btnGetPKCERefreshToken.addEventListener("click", function (evt) {
        dropboxTokenManagement.retrieveTokenPKCERefresh({
          authorizationEndpoint: dropboxAuthorizationEndpoint,
        });
      });
      pRefreshToken.appendChild(btnGetPKCERefreshToken);
      const btnCreateAccessToken = document.createElement("button");
      btnCreateAccessToken.innerHTML = "Create Access Token";
      btnCreateAccessToken.addEventListener("click", function (evt) {
        dropboxTokenManagement.refreshAccessTokenPKCE();
      });
      pRefreshToken.appendChild(btnCreateAccessToken);
      const spanRefreshToken = document.createElement("span");
      spanRefreshToken.append(dropboxTokenManagement.getRefreshToken());
      dropboxTokenManagement.setCallbackRefreshToken(function (strToken) {
        spanRefreshToken.innerHTML = "";
        spanRefreshToken.append(strToken);
      });
      pRefreshToken.appendChild(spanRefreshToken);
      div.appendChild(pRefreshToken);
  
      const btnListFolder = document.createElement("button");
      btnListFolder.innerHTML = "List Folder";
      btnListFolder.addEventListener("click", function (evt) {
        list_folder();
      });
      div.appendChild(btnListFolder);
      const inpPath = document.createElement("input");
      inpPath.type = "text";
      div.appendChild(inpPath);
      const btnDownload = document.createElement("button");
      btnDownload.innerHTML = "Download";
      btnDownload.addEventListener("click", function (evt) {
        download(inpPath.value);
      });
      div.appendChild(btnDownload);
      document.body.appendChild(div);
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
        const reqFileList = createRequestPOST("https://api.dropboxapi.com/2/files/list_folder", blobReqBody, []);
        const respFileList = await dropboxTokenManagement.fetch(reqFileList);
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
        const headers = [ [ "Dropbox-API-Arg",  jsonReqArg ] ];
        const reqDownload = createRequestPOST("https://content.dropboxapi.com/2/files/download", null, headers);
        const respDownload = await dropboxTokenManagement.fetch(reqDownload);
        if (respDownload.status === 200) {
          const jsonResult = respDownload.headers.get("dropbox-api-result");
          const objRespBody = JSON.parse(jsonResult);
          console.log(objRespBody);
          const strRespBody = await respDownload.text();
          console.log(strRespBody);
        }
      }
    }
    const btnStart = document.createElement("button");
    btnStart.append("Start");
    btnStart.addEventListener("click", function () {
      createTokenManager({
        clientId: getClientId(),
        tokenEndpoint: dropboxTokenEndpoint,
      });
      btnStart.remove();
    });
    document.body.appendChild(btnStart);
    function getClientId() {
      const clientId = window.prompt("Enter app ID:");
      return clientId;
    }
    OAuth2.receivedTokens.then(function (tokens) {
      if (tokens.tokenEndpoint === dropboxTokenEndpoint.toString()) {
        createTokenManager(tokens);
      }
    }).catch(function (error) {
      console.error(error);
    });
  } catch (e) {
    console.error(e);
  }
}

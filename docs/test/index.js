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

function start([ evtWindow ]) {
  try {
    const urlThis = new self.URL(window.location);
    console.log(window.location);
    console.log(urlThis);
    const fragment = urlThis.hash.substring(1);
    const paramsThis = new self.URLSearchParams(fragment);
    console.log(fragment);
    console.log(paramsThis);
    let strToken = paramsThis.get("access_token");
    
    const btnSetToken = document.createElement("button");
    btnSetToken.innerHTML = "Set Token";
    btnSetToken.addEventListener("click", function (evt) {
      while (!strToken) {
        strToken = window.prompt("Enter the access token: ");
      }
    });
    document.body.appendChild(btnSetToken);

    const btnGetPKCEToken = document.createElement("button");
    btnGetPKCEToken.innerHTML = "Get PKCE Token";
    btnGetPKCEToken.addEventListener("click", function (evt) {
      (async function () {
        const code_verifier = base64UrlEncode(strRaw32Random());
        const bytesHash = await self.crypto.subtle.digest("SHA-256", bytesFromRaw(code_verifier));
        const code_challenge = base64UrlEncode(bytesHash);
        const params = new URLSearchParams([
          [ "client_id", "m1po2j6iw2k75n4" ],
          [ "redirect_uri", "https://scotwatson.github.io/DropboxTest/test/index.html" ],
          [ "response_type", token ],
          [ "code_challenge", code_challenge ],
          [ "code_challenge_method", "S256" ],
        ]);
        const urlAuthorize = new URL("https://www.dropbox.com/oauth2/authorize?" + params);
        const req = createRequestGET(urlAuthorize);
        const resp = await fetch(req);
        console.log(resp);
      })();
    });
    document.body.appendChild(btnGetPKCEToken);


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
    const btnRevokeToken = document.createElement("button");
    btnRevokeToken.innerHTML = "Revoke Token";
    btnRevokeToken.addEventListener("click", function (evt) {
      revokeToken();
    });
    document.body.appendChild(btnRevokeToken);
    function strRaw32Random() {
      const buffer = new Uint8Array(32);
      self.crypto.getRandomValues(buffer);
      let ret = "";
      for (const byte of buffer) {
        ret += String.fromCharCode(byte);
      }
      return ret;
    }
    function bytesFromRaw(strRaw) {
      const ret = new Uint8Array(strRaw.length);
      for (let i = 0; i < strRaw.length; ++i) {
        ret[i] = strRaw.charCodeAt(i);
      }
      return ret.buffer;
    }
    function base64UrlEncode(strRaw) {
      return btoa(strRaw).replace("+", "-").replace("/", "_");
    }
    function base64UrlDecode(strBase64URL) {
      const strBase64 = strBase64URL.replace("-", "+").replace("_", "/");
      return atob(strBase64);
    }
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
      const headers = [ [ "Authorization", "Bearer " + strToken ] ];
      const reqFileList = createRequestPOST("https://api.dropboxapi.com/2/files/list_folder", blobReqBody, headers);
      const respFileList = await fetch(reqFileList);
      console.log(respFileList);
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
      const headers = [ [ "Authorization", "Bearer " + strToken ], [ "Dropbox-API-Arg",  jsonReqArg ] ];
      const reqDownload = createRequestPOST("https://content.dropboxapi.com/2/files/download", null, headers);
      const respDownload = await fetch(reqDownload);
      console.log(respDownload);
      if (respDownload.status === 200) {
        const jsonResult = respDownload.headers.get("dropbox-api-result");
        const objRespBody = JSON.parse(jsonResult);
        console.log(objRespBody);
        const strRespBody = await respDownload.text();
        console.log(strRespBody);
      }
    }
    async function revokeToken() {
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

/*
Copyright (C) 2022 Lukas Buchs
license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
*/

/**
 * creates a new FIDO2 registration
 * step 1: get create arguments from server (getCreateArgs)
 *    this step will return a challenge
 * step 2: call navigator.credentials.create with the arguments returned in step 1
 *    this will prompt the user to register a new authenticator, e.g. use a passwords app
 * step 3: send the response to the server for processing
 *    including credentialId, AAGUID(device identifier) and credentialPublicKey,
 *    which will be saved on a db in order to validate later logins by the same user.
 *
 * @param {String} webauthnParams - URL parameters for the WebAuthn request,
 *  we use the following parameter combination in this implementation
      '&type_int=1' +
      '&type_hybrid=1' +
      '&fmt_none=1' +
      '&rpId=' + encodeURIComponent(domainname) +
      '&userId=' + encodeURIComponent(usr_token) +
      '&userName=' + encodeURIComponent(email) +
      '&userDisplayName=' + encodeURIComponent(userDisplayName) +
      '&userVerification=discouraged'
 *
 * @returns {undefined}
 */

const webauthnServer = "https://localhost/webauthn/webauthn/server.php";

export async function createRegistration(webauthnParams) {
  try {

    // check browser support
    if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
      throw new Error('Browser not supported.');
    }

    // get create args
    let url = webauthnServer + '?fn=getCreateArgs' + webauthnParams;

    let rep = await window.fetch(url, {
      method: 'GET',
      cache: 'no-cache'
    });
    const createArgs = await rep.json();

    // error handling
    if (createArgs.success === false) {
      throw new Error(createArgs.msg || 'unknown error occured');
    }

    // replace binary base64 data with ArrayBuffer. a other way to do this
    // is the reviver function of JSON.parse()
    recursiveBase64StrToArrayBuffer(createArgs);

    // create credentials
    const cred = await navigator.credentials.create(createArgs);

    // create object
    const authenticatorAttestationResponse = {
      transports: cred.response.getTransports ? cred.response.getTransports() : null,
      clientDataJSON: cred.response.clientDataJSON ? arrayBufferToBase64(cred.response.clientDataJSON) : null,
      attestationObject: cred.response.attestationObject ? arrayBufferToBase64(cred.response.attestationObject) : null
    };

    // check auth on server side
    rep = await window.fetch(webauthnServer + '?fn=processCreate' + webauthnParams, {
      method: 'POST',
      body: JSON.stringify(authenticatorAttestationResponse),
      cache: 'no-cache'
    });
    if (!rep.ok) {
      throw new Error('Network response was not ok: ' + rep.statusText);
    }

    const authenticatorAttestationServerResponse = await rep.json();

    // prompt server response
    if (authenticatorAttestationServerResponse.success) {
      window.alert(authenticatorAttestationServerResponse.msg || 'registration success');

    } else {
      throw new Error(authenticatorAttestationServerResponse.msg);
    }

  } catch (err) {
    window.alert(err.message || 'unknown error occured');
  }
  return true;
}


/**
 * checks a FIDO2 registration upon login
 * step 1: get get arguments from server (getGetArgs)
 *    this step will return a challenge
 * step 2: call navigator.credentials.get with the arguments returned in step 1
 *    this will prompt the user to authenticate with a registered authenticator,
 *    e.g. use a passwords app or biometrics or a security key
 * step 3: send the response to the server for processing
 *    including credentialId, AAGUID(device identifier) and signature,
 *    which will be checked against the db in order to validate the user.
 * @returns {undefined}
 */
export async function checkRegistration(webauthnParams) {
  try {

    if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
      throw new Error('Browser not supported.');
    }

    // get check args
    let rep = await window.fetch(webauthnServer + '?fn=getGetArgs' + webauthnParams, {
      method: 'GET',
      cache: 'no-cache'
    });
    const getArgs = await rep.json();

    // error handling
    if (getArgs.success === false) {
      throw new Error(getArgs.msg);
    }

    // replace binary base64 data with ArrayBuffer. a other way to do this
    // is the reviver function of JSON.parse()
    recursiveBase64StrToArrayBuffer(getArgs);

    // check credentials with hardware
    const cred = await navigator.credentials.get(getArgs);

    // create object for transmission to server
    const authenticatorAttestationResponse = {
      id: cred.rawId ? arrayBufferToBase64(cred.rawId) : null,
      clientDataJSON: cred.response.clientDataJSON ? arrayBufferToBase64(cred.response.clientDataJSON) : null,
      authenticatorData: cred.response.authenticatorData ? arrayBufferToBase64(cred.response.authenticatorData) : null,
      signature: cred.response.signature ? arrayBufferToBase64(cred.response.signature) : null,
      userHandle: cred.response.userHandle ? arrayBufferToBase64(cred.response.userHandle) : null
    };

    // send to server
    rep = await window.fetch(webauthnServer + '?fn=processGet' + webauthnParams, {
      method: 'POST',
      body: JSON.stringify(authenticatorAttestationResponse),
      cache: 'no-cache'
    });
    const authenticatorAttestationServerResponse = await rep.json();

    // check server response
    if (authenticatorAttestationServerResponse.success) {
      window.alert(authenticatorAttestationServerResponse.msg || 'login success');
    } else {
      throw new Error(authenticatorAttestationServerResponse.msg);
    }

  } catch (err) {
    window.alert(err.message || 'unknown error occured');
  }
}

export function clearRegistrationsForUser(webauthnParams) {
  console.log('clearRegistrationsForUser', webauthnParams);

  window.fetch(webauthnServer + '?fn=clearRegistrations' + webauthnParams, { method: 'GET', cache: 'no-cache' }).then(function (response) {
    return response.json();

  }).then(function (json) {
    if (json.success) {
      window.alert(json.msg);
    } else {
      throw new Error(json.msg);
    }
  }).catch(function (err) {
    window.alert(err.message || 'unknown error occured');
  });
}


export function queryFidoMetaDataService(webauthnParams) {
  window.fetch(webauthnServer + '?fn=queryFidoMetaDataService' + webauthnParams, { method: 'GET', cache: 'no-cache' }).then(function (response) {
    return response.json();

  }).then(function (json) {
    if (json.success) {
      window.alert(json.msg);
    } else {
      throw new Error(json.msg);
    }
  }).catch(function (err) {
    window.alert(err.message || 'unknown error occured');
  });
}

/**
 * convert RFC 1342-like base64 strings to array buffer
 * @param {mixed} obj
 * @returns {undefined}
 */
function recursiveBase64StrToArrayBuffer(obj) {
  let prefix = '=?BINARY?B?';
  let suffix = '?=';
  if (typeof obj === 'object') {
    for (let key in obj) {
      if (typeof obj[key] === 'string') {
        let str = obj[key];
        if (str.substring(0, prefix.length) === prefix && str.substring(str.length - suffix.length) === suffix) {
          str = str.substring(prefix.length, str.length - suffix.length);

          let binary_string = window.atob(str);
          let len = binary_string.length;
          let bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
          }
          obj[key] = bytes.buffer;
        }
      } else {
        recursiveBase64StrToArrayBuffer(obj[key]);
      }
    }
  }
}

/**
 * Convert a ArrayBuffer to Base64
 * @param {ArrayBuffer} buffer
 * @returns {String}
 */
function arrayBufferToBase64(buffer) {
  let binary = '';
  let bytes = new Uint8Array(buffer);
  let len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

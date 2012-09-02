/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is DOMCrypt API code.
 *
 * The Initial Developer of the Original Code is
 * the Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *  David Dahl <ddahl@mozilla.com>  (Original Author)
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

const {Cc, Ci, Cr, Cu, components} = require("chrome");
const winUtils = require("window-utils");
const {data} = require('self');
const base64Encode = require("api-utils/base64").encode;
const logger = require('util/logger').create("domcrypt.js");

var {ChromeWorker, Services} = Cu.import("resource://gre/modules/Services.jsm", null);
var {XPCOMUtils} = Cu.import("resource://gre/modules/XPCOMUtils.jsm");
var {ctypes} = Cu.import("resource://gre/modules/ctypes.jsm");
var {Services} = Cu.import("resource://gre/modules/Services.jsm");

// Constants to describe all operations
const GENERATE_KEYPAIR  = "generateKeypair";
const GENERATE_RANDOM   = "generateRandom";
const ENCRYPT           = "encrypt";
const DECRYPT           = "decrypt";
const SIGN              = "sign";
const VERIFY            = "verify";
const VERIFY_PASSPHRASE = "verifyPassphrase";
const INITIALIZE_WORKER = "init";

const KEYPAIR_GENERATED = "keypairGenerated";
const RANDOM_GENERATED = "randomGenerated";
const DATA_ENCRYPTED = "dataEncrypted";
const DATA_DECRYPTED = "dataDecrypted";
const MESSAGE_SIGNED = "messageSigned";
const MESSAGE_VERIFIED = "messageVerified";
const PASSPHRASE_VERIFIED = "passphraseVerified";
const WORKER_ERROR = "error";

var Callbacks = {

  encrypt: { callback: [], sandbox: null },

  decrypt: { callback: [], sandbox: null },

  generateKeypair: { callback: [], sandbox: null },

  generateRandom: { callback: [], sandbox: null },

  sign: { callback: [], sandbox: null },

  verify: { callback: [], sandbox: null },

  sandbox : null,

  /**
   * Register a callback for any API method
   *
   * @param string aLabel
   * @param function aCallback
   * @param Object aSandbox
   * @returns void
   */
  register: function GCO_register(aLabel, aCallback)
  {
    // we need a 'fall back' sandbox for prompts, etc. when we are unsure what
    // method is in play


    this[aLabel].sandbox = this.sandbox;
    this[aLabel].callback.push(aCallback);
  },

  /**
   * wrap the content-provided script in order to make it easier
   * to import and run in the sandbox
   *
   * @param string aPubKey
   * @returns function
   */
  makeGenerateKeypairCallback:
  function DA_makeGenerateKeypairCallback(aPubKey)
  {
    let self = this;
    let callback = function generateKeypair_callback()
                   {
                     self.generateKeypair.callback[0](aPubKey);
                     self.generateKeypair.callback = self.generateKeypair.callback.slice(1);
                   };
    return callback;
  },

  /**
   * Wraps the content callback script, imports it into the sandbox and
   * calls it in the sandbox
   * @param Object aKeypair
   * @returns void
   */
  handleGenerateKeypair: function GCO_handleGenerateKeypair(aKeypairData)
  {
    // XXX password is entered before creating keypair
    let sandbox = this.generateKeypair.sandbox;
    let callback = this.makeGenerateKeypairCallback(aKeypairData);
    sandbox.importFunction(callback, "generateKeypairCallback");
    Cu.evalInSandbox("generateKeypairCallback();", sandbox, "1.8", "DOMCrypt", 1);
  },

  /**
   * wrap the content-provided script in order to make it easier
   * to import and run in the sandbox
   *
   * @param number aLength
   * @returns function
   */
  makeGenerateRandomCallback:
  function DA_makeGenerateRandomCallback(aLength)
  {
    let self = this;
    let callback = function generateRandom_callback()
                   {
                     self.generateRandom.callback[0](aLength);
                     self.generateRandom.callback = self.generateRandom.callback.slice(1);
                   };
    return callback;
  },

  /**
   * Wraps the content callback script, imports it into the sandbox and
   * calls it in the sandbox
   * @param Object aLength
   * @returns void
   */
  handleGenerateRandom: function GCO_handleGenerateRandom(aLength)
  {
    let sandbox = this.generateRandom.sandbox;
    let callback = this.makeGenerateRandomCallback(aLength);
    sandbox.importFunction(callback, "generateRandomCallback");
    Cu.evalInSandbox("generateRandomCallback();", sandbox, "1.8", "DOMCrypt", 1);
  },

  /**
   * wrap the content-provided encrypt callback script in order to make it easier
   * to import and run in the sandbox
   *
   * @param Object aCipherMessage
   * @returns JS function
   */
  makeEncryptCallback:
  function DA_encryptCallback(aCipherMessage)
  {
    let self = this;
    let callback = function encrypt_callback()
                   {
                     self.encrypt.callback[0](aCipherMessage);
                     self.encrypt.callback = self.encrypt.callback.slice(1);
                   };
    return callback;
  },

  /**
   * Wraps the content callback script which deals with encrypted message objects
   *
   * @param Object aCipherMessage
   * @returns void
   */
  handleEncrypt: function GCO_handleEncrypt(aCipherMessage)
  {
    let callback = this.makeEncryptCallback(aCipherMessage);
    let sandbox = this.encrypt.sandbox;
    sandbox.importFunction(callback, "encryptCallback");
    Cu.evalInSandbox("encryptCallback();",
                     sandbox, "1.8", "DOMCrypt", 1);
  },

  /**
   * wrap the content-provided decrypt callback script in order to make it easier
   * to import and run in the sandbox
   *
   * @param string aPlainText
   * @returns JS function
   */
  makeDecryptCallback:
  function DA_decryptCallback(aPlainText)
  {
    let self = this;
    let callback = function decrypt_callback()
                   {
                     self.decrypt.callback[0](aPlainText);
                     self.decrypt.callback = self.decrypt.callback.slice(1);
                   };
    return callback;
  },

  /**
   * Wraps the content callback script which deals with the decrypted string
   *
   * @param string aPlainText
   * @returns void
   */
  handleDecrypt: function GCO_handleDecrypt(aPlainText)
  {
    let callback = this.makeDecryptCallback(aPlainText);
    let sandbox = this.decrypt.sandbox;
    sandbox.importFunction(callback, "decryptCallback");
    Cu.evalInSandbox("decryptCallback();",
                     sandbox, "1.8", "DOMCrypt", 1);
  },

  /**
   * Wraps the content callback script which deals with the signature
   *
   * @param string aSignature
   * @returns void
   */
  makeSignCallback: function GCO_makeSignCallback(aSignature)
  {
    let self = this;
    let callback = function sign_callback()
                   {
                     self.sign.callback[0](aSignature);
                     self.sign.callback = self.sign.callback.slice(1);
                   };
    return callback;
  },

  /**
   * Executes the signature callback function in the sandbox
   *
   * @param string aSignature
   * @returns void
   */
  handleSign: function GCO_handleSign(aSignature)
  {
    let callback = this.makeSignCallback(aSignature);
    let sandbox = this.sign.sandbox;
    sandbox.importFunction(callback, "signCallback");
    Cu.evalInSandbox("signCallback();",
                     sandbox, "1.8", "DOMCrypt", 1);
  },

  /**
   * Wraps the content callback script which deals with the signature verification
   *
   * @param boolean aVerification
   * @returns void
   */
  makeVerifyCallback: function GCO_makeVerifyCallback(aVerification)
  {
    let self = this;
    let callback = function verify_callback()
                   {
                     let len = self.verify.callback.length;
                     self.verify.callback[0](aVerification);
                     self.verify.callback = self.verify.callback.slice(1);
                   };
    return callback;
  },

  /**
   * Executes the verification callback function in the sandbox
   *
   * @param boolean aVerification
   * @returns void
   */
  handleVerify: function GCO_handleVerify(aVerification)
  {
    let callback = this.makeVerifyCallback(aVerification);
    let sandbox = this.verify.sandbox;
    sandbox.importFunction(callback, "verifyCallback");
    Cu.evalInSandbox("verifyCallback();",
                     sandbox, "1.8", "DOMCrypt", 1);
  },
};

var Domcrypt = {
  worker: null,
  /**
   * Remove all references to windows on window close or browser shutdown
   *
   * @returns void
   */
  shutdown: function DCM_shutdown()
  {
    this.worker.postMessage(JSON.stringify({ action: "shutdown" }));
  
    for (let prop in Callbacks) {
      Callbacks[prop].callback = null;
      Callbacks[prop].sandbox = null;
    }
    Callbacks = null;
  },
  
  /////////////////////////////////////////////////////////////////////////
  // DOMCrypt API methods exposed via the nsIDOMGlobalPropertyInitializer
  /////////////////////////////////////////////////////////////////////////
  
  /**
   * The internal 'generateKeypair' method that calls the this.worker
   *
   * @param string aPassphrase
   * @returns void
   */
  generateKeypair: function DCM_generateKeypair(keyType, keypairBits, aCallback)
  {
    Callbacks.register(GENERATE_KEYPAIR, aCallback);
    this.worker.postMessage(JSON.stringify({ action: GENERATE_KEYPAIR, keyType: keyType, keypairBits: keypairBits }));
  },
  
  /**
   * The internal 'encrypt' method which calls the this.worker to do the encrypting
   *
   * @param string aPlainText
   * @param string aPublicKey
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  encrypt: function DCM_encrypt(aPlainText, aPublicKey, aCallback)
  {
    Callbacks.register(ENCRYPT, aCallback);
  
    this.worker.postMessage(JSON.stringify({ action: ENCRYPT,
                         pubKey: aPublicKey,
                         plainText: aPlainText
                       }));
  },
  
  /**
   * The internal 'decrypt' method which calls the this.worker to do the decrypting
   *
   * @param Object aCipherMessage
   * @param string aPassphrase
   * @returns void
   */
  decrypt:
  function DCM_decrypt(aCipherMessage, derSecKey, aCallback)
  {
    Callbacks.register(DECRYPT, aCallback);
  
    this.worker.postMessage(JSON.stringify({ action: DECRYPT,
                         aCipherMessage: aCipherMessage,
                         derSecKey: derSecKey
                       }));
  },
  
  /**
   * Front-end 'sign' method prompts user for passphrase then
   * calls the internal _sign message
   *
   * @param string aPlainTextMessage
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  sign: function DCM_sign(aPlainTextMessage, derSecKey, derPubKey, aCallback)
  {
    Callbacks.register(SIGN, aCallback);
    this._sign(aPlainTextMessage, derSecKey, derPubKey);
  },
  
  /**
   * Internal backend '_sign' method calls the this.worker to do the actual signing
   *
   * @param string aPlainTextMessage
   * @param string aPassphrase
   * @returns void
   */
  _sign: function DCM__sign(aPlainTextMessage, derSecKey, derPubKey)
  {
    let userPrivKey = derSecKey;
    let hash = base64Encode(aPlainTextMessage);
  
    this.worker.postMessage(JSON.stringify({ action: SIGN,
                         hash: hash,
                         derSecKey: derSecKey,
                         derPubKey: derPubKey
                       }));
  },
  
  /**
   * The 'verify' method which calls the this.worker to do signature verification
   *
   * @param string aPlainTextMessage
   * @param string aSignature
   * @param string aPublicKey
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  verify:
  function
  DCM_verify(aPlainTextMessage, aSignature, aPublicKey, aCallback)
  {
    Callbacks.register(VERIFY, aCallback);
    let hash = aPlainTextMessage;
  
    // Create a hash in the this.worker for verification
    this.worker.postMessage(JSON.stringify({ action: VERIFY,
                         hash: hash,
                         signature: aSignature,
                         pubKey: aPublicKey
                       }));
  },
  
  generateRandom: function DCM_generateRandom(aLength, aCallback)
  {
    Callbacks.register(GENERATE_RANDOM, aCallback);
  
    if (!aLength) {
      aLength = 1;
    }
  
    this.worker.postMessage(JSON.stringify({ action: GENERATE_RANDOM,
                         aLength: aLength 
                       }));
  },
  
  /**
   * Creates a unique callback registry for each DOMCryptMethods object
   *
   * @returns Object
   */
  
  /**
   * Initialize the DOMCryptMethods object by getting the configuration object
   * and creating the callbacks object
   * @param outparam aDOMCrypt
   * @returns void
   */
  init: function() 
  {
    var _window = XPCNativeWrapper.unwrap(winUtils.activeWindow);
    Callbacks.sandbox = Cu.Sandbox( _window, { sandboxPrototype: _window, wantXrays: false });
    this.worker = new ChromeWorker(data.url("workers/domcrypt_worker.js"));
    this.worker.onmessage = function DCM_worker_onmessage(aEvent) {
        var data = JSON.parse(aEvent.data);
        switch (data.action) {
        case KEYPAIR_GENERATED:
          Callbacks.handleGenerateKeypair(data.keypairData);
          break;
        case RANDOM_GENERATED:
          Callbacks.handleGenerateRandom(data.randomBytes.randomBytes);
          break;
        case DATA_ENCRYPTED:
          Callbacks.handleEncrypt(data.cipherMessage);
          break;
        case DATA_DECRYPTED:
          Callbacks.handleDecrypt(data.plainText);
          break;
        case MESSAGE_SIGNED:
          Callbacks.handleSign(data.signature);
          break;
        case MESSAGE_VERIFIED:
          Callbacks.handleVerify(data.verification);
          break;
        case WORKER_ERROR:
          if (data.notify) {
            notifyUser(data);
          }
        default:
          break;
        }
    };
    this.worker.onerror = function DCM_onerror(aError) {
      logger.error(aError);
    };

    // Full path to NSS via js-ctypes
    let path = Services.dirsvc.get("GreD", Ci.nsILocalFile);
    let libName = ctypes.libraryName("nss3"); // platform specific library name
    path.append(libName);
    this.worker.postMessage(JSON.stringify({action: INITIALIZE_WORKER, nssPath: path.path}));
  }
}

Domcrypt.init(); 

exports.domcrypt = Domcrypt;

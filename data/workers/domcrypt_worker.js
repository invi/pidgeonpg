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
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is
 * the Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2010
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *  Justin Dolske <dolske@mozilla.com> (original author)
 *  David Dahl <ddahl@mozilla.com>
 *  Sergio Ruiz <invi@pidgeonpg.org> [1]
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

/**
 * NOTES:
 *
 * The WeaveCrypto object in this file was originally pulled from hg.mozilla.org
 *
 * http://hg.mozilla.org/mozilla-central/ \
 * raw-file/d0c40fc38702/services/crypto/modules/WeaveCrypto.js
 *
 * WeaveCrypto's API as it was released in Firefox 4 was reduced in scope due
 * to Sync's move to J-Pake, hence the need for this more complete version.
 *
 * This version has the additional APIs 'sign' and 'verify' and has been
 * edited for use in a ChromeWorker.
 *
 * [1] This version has been modified for direct public and private key import 
 * in DER format to support sign, verify, encrypt and decrypt in
 * such case. Also DSA and ElGamal key generation has been added. 
 *
 */

var DEBUG = false;

const PUB_ALGO = {
  RSA: 1, 
  RSA_E: 2,
  RSA_S: 3,
  ELGAMAL_E: 16,
  DSA: 17, 
  ECDH: 18,
  ECDSA: 19,
  ELGAMAL: 20
}

function log(aMessage) {
  if (!DEBUG){
    return;
  }
  var _msg = "domcrypt_worker: " + " " + aMessage + "\n";
  dump(_msg);
}

const GENERATE_KEYPAIR  = "generateKeypair";
const GENERATE_RANDOM   = "generateRandom";
const ENCRYPT           = "encrypt";
const DECRYPT           = "decrypt";
const SIGN              = "sign";
const VERIFY            = "verify";
const GENERATE_SYM_KEY  = "generateSymKey";
const SYM_ENCRYPT       = "symEncrypt";
const SYM_DECRYPT       = "symDecrypt";
const WRAP_SYM_KEY      = "wrapSymKey";
const VERIFY_PASSPHRASE = "verifyPassphrase";
const SHUTDOWN          = "shutdown";
const INITIALIZE        = "init";


onmessage = function(aEvent) {
  var data = JSON.parse(aEvent.data);
  switch(data.action) {
    case INITIALIZE:
      WeaveCrypto.initNSS(data.nssPath);
      DEBUG = data.debug || false;
      break;
    case GENERATE_KEYPAIR:
      result = WeaveCryptoWrapper.generateKeypair(data.keyType, data.keypairBits);
      postMessage(JSON.stringify({ keypairData: result, action: "keypairGenerated" }));
      break;
    case GENERATE_RANDOM:
      result = WeaveCryptoWrapper.generateRandom(data.aLength);
      postMessage(JSON.stringify({ randomBytes: result, action: "randomGenerated" }));
      break;
    case ENCRYPT:
      result = WeaveCryptoWrapper.encrypt(data.plainText, data.pubKey);
      postMessage(JSON.stringify({ cipherMessage: result, action: "dataEncrypted" }));
      break;
    case DECRYPT:
      result = WeaveCryptoWrapper.decrypt(data.aCipherMessage,
                                          data.derSecKey);
    
      postMessage(JSON.stringify({ plainText: result, action: "dataDecrypted" }));
      break;
    case SIGN:
      result = WeaveCryptoWrapper.sign(data.hash,
                                       data.derSecKey,
                                       data.derPubKey);
    
      postMessage(JSON.stringify({ signature: result, action: "messageSigned" }));
      break;
    case VERIFY:
      result = WeaveCryptoWrapper.verify(data.hash,
                                         data.signature,
                                         data.pubKey);
    
      postMessage(JSON.stringify({ verification: result, action: "messageVerified" }));
      break;
    case SHUTDOWN:
      WeaveCrypto.shutdown();
    default:
      break;
  }
}


/**
 * WeaveCryptoWrapper
 *
 * Wrap the WeaveCrypto API in a more elegant way. This is very similar to the
 * original DOMCrypt extension code
 *
 */
var WeaveCryptoWrapper = {

  /**
   * generateKeypair
   *
   * Create a KeyPair for general purpose 
   *
   * @param int Type of Key algorithm 
   *        int Key length in bits
   * @returns object
   *          The object returned looks like:
   *          { action:  "keypairGenerated",
   *            privKey: <PRIVATE KEY>,
   *            created: <DATE CREATED>
   *          }
   */
  generateKeypair: function WCW_generateKeypair(keyType, keypairBits)
  {
    var privOut = {};

    try {
      WeaveCrypto.generateKeypair(keyType, keypairBits, privOut);
      let results = { action: "keypairGenerated",
                      privKey: privOut,
                      created: Date.now()
                    };
      return results;
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
      throw(ex);
    }
  },

  /**
   * generateRandom
   *
   * Create a random bytes
   *
   * @param int Numbes of random bytes to create
   * @returns object
   *          The object returned looks like:
   *          { action:  "randomGenerated",
   *            randomBytes: <STRING OF RANDOM BYTES>
   *          }
   */
  generateRandom: function WCW_generateRandom(nbytes)
  {

    try {
      var randomBytes = WeaveCrypto.generateRandomBytes(nbytes);

      let results = { action: "randomGenerated",
                      randomBytes: randomBytes
                    };
      return results;
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
      throw(ex);
    }
  },

  /**
   * encrypt
   *
   * Encrypt data with a public key
   *
   * @param string aSessionkey
   *        The base64 session key data that will be encrypted
   * @param string aPublicKey
   *        The recipient's DER base64 encoded public key
   * @returns Object
   *          A 'message' object:
   *          { content:    <ENCRYPTED_STRING>,
   *            pubKey:     <RECIPIENT PUB_KEY>,
   *            wrappedKey: <WRAPPED SYM_KEY>,
   *            iv:         <INITIALIZATION VECTOR>
   *          }
   */
  encrypt: function WCW_encrypt(aSessionkey, aPublicKey)
  {
    if (!aSessionkey && !aPublicKey) {
      throw new Error("Missing Arguments: aSessionkey and aPublicKey are required");
    }
    try {
      var encryptedSessionkey = WeaveCrypto.encrypt(aSessionkey, aPublicKey);
      return  encryptedSessionkey;
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
      throw ex;
    }
  },

  /**
   * decrypt
   *
   * Decrypt encrypted data with a private key
   *
   * @param string aSessionkey
   *        The base64 encrypted session key
   * @param string aPrivateKey
   *        The base64 encoded private key string
   * @returns string
   *          The decrypted message in base64
   */
  decrypt: function WCW_decrypt(aSessionkey, aPrivateKey)
  {
    try {
      var decrypted = WeaveCrypto.decrypt(aSessionkey, aPrivateKey);
      return decrypted;
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
      throw(ex);
    }
  },

  /**
   * Cryptographically sign a message
   *
   * @param string aHash
   *        A base64 signature data hash of the message
   * @param string aPrivateKey
   *        The sender's base64 DER encoded private key
   * @param string aPublicKey
   *        The sender's base64 DER encoded public key
   */
  sign: function WCW_sign(aHash, aPrivateKey, aPublicKey)
  {
    var signature;
    try {
      signature = WeaveCrypto.sign(aPrivateKey, aPublicKey, aHash);
      return signature;
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
      throw ex;
    }
  },

  /**
   * Verify a signature was created by the sender
   *
   * @param string aData
   *        A base64 signature data 
   * @param string aSignature
   *        A base64 encoded signature string
   * @param string aPublicKey
   *        The sender's base 64 DER encoded public key
   * @returns boolean
   */
  verify: function WCW_verify(aData, aSignature, aPublicKey)
  {
    try {
      let results = WeaveCrypto.verify(aPublicKey, aSignature, aData);

      if (results)
        return true;

      return false;
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
      throw ex;
    }
  },
};

/**
 * The WeaveCrypto changes I have made are minimal:
 * 1. Removed any calls into Cc/Ci/Cr, etc.
 * 2. added WeaveCrypto.sign() (PK11_Sign)
 * 3. added WeaveCrypto.verify() (PK11_Verify)
 *
 * WeaveCrypto (js-ctypes iteration) was coded and reviewed in this bug:
 * https://bugzilla.mozilla.org/show_bug.cgi?id=513798
 *
 */

// http://mxr.mozilla.org/mozilla-central/source/security/nss/lib/util/secoidt.h#318
// recommended EC algs: http://www.nsa.gov/business/programs/elliptic_curve.shtml
// http://mxr.mozilla.org/mozilla-central/source/security/nss/lib/util/secoidt.h#346

var WeaveCrypto = {

  debugEnabled : false,
  nss          : null,
  nss_t        : null,

  log : function (message) {
    if (!this.debugEnabled)
      return;
    dump("WeaveCrypto: " + message + "\n");
  },

  shutdown : function WC_shutdown() {
    this.log("closing nsslib");
    this.nsslib.close();
  },

  fullPathToLib: null,

  initNSS : function WC_initNSS(aNSSPath, debugEnabled) {
    // Open the NSS library.
    this.fullPathToLib = aNSSPath;
    this.debugEnabled = debugEnabled || false;
    // XXX really want to be able to pass specific dlopen flags here.
    var nsslib = ctypes.open(this.fullPathToLib);
    this.nsslib = nsslib;

    this.log("Initializing NSS types and function declarations...");

    this.nss = {};
    this.nss_t = {};

    // nsprpub/pr/include/prtypes.h#435
    // typedef PRIntn PRBool; --> int
    this.nss_t.PRBool = ctypes.int;
    // security/nss/lib/util/seccomon.h#91
    // typedef enum
    this.nss_t.SECStatus = ctypes.int;
    // security/nss/lib/softoken/secmodt.h#59
    // typedef struct PK11SlotInfoStr PK11SlotInfo; (defined in secmodti.h)
    this.nss_t.PK11SlotInfo = ctypes.void_t;
    // security/nss/lib/util/pkcs11t.h
    this.nss_t.CK_MECHANISM_TYPE = ctypes.unsigned_long;
    this.nss_t.CK_ATTRIBUTE_TYPE = ctypes.unsigned_long;
    this.nss_t.CK_KEY_TYPE       = ctypes.unsigned_long;
    this.nss_t.CK_OBJECT_HANDLE  = ctypes.unsigned_long;
    // security/nss/lib/util/seccomon.h#64
    // typedef enum
    this.nss_t.SECItemType = ctypes.int;
    // SECItemType enum values...
    this.nss.SIBUFFER = 0;
    // Needed for SECKEYPrivateKey struct def'n, but I don't think we need to actually access it.
    this.nss_t.PLArenaPool = ctypes.void_t;
    // security/nss/lib/cryptohi/keythi.h#45
    // typedef enum
    this.nss_t.KeyType = ctypes.int;
    // security/nss/lib/softoken/secmodt.h#201
    // typedef PRUint32 PK11AttrFlags;
    this.nss_t.PK11AttrFlags = ctypes.unsigned_int;

    // security/nss/lib/util/seccomon.h#83
    // typedef struct SECItemStr SECItem; --> SECItemStr defined right below it
    this.nss_t.SECItem = ctypes.StructType(
      "SECItem", [{ type: this.nss_t.SECItemType },
                  { data: ctypes.unsigned_char.ptr },
                  { len : ctypes.int }]);

    // security/nss/lib/softoken/secmodt.h#65
    // typedef struct PK11RSAGenParamsStr --> def'n on line 139
    this.nss_t.PK11RSAGenParams = ctypes.StructType(
      "PK11RSAGenParams", [{ keySizeInBits: ctypes.int },
                           { pe : ctypes.unsigned_long }]);

    // security/nss/lib/softoken/secmodt.h#65
    // typedef struct PK11RSAGenParamsStr --> def'n on line 132
    // struct SECKEYDHParamsStr {
    //     PLArenaPool * arena;
    //     SECItem prime; /* p */
    //     SECItem base; /* g */
    // };
    this.nss_t.SECKEYDHParams = ctypes.StructType(
      "SECKEYDHParams", [{ arena:        this.nss_t.PLArenaPool.ptr  },
                         { prime:        this.nss_t.SECItem         },
                         { base:        this.nss_t.SECItem         },]);

    // security/nss/lib/cryptohi/keythi.h#233
    // typedef struct SECKEYPrivateKeyStr SECKEYPrivateKey; --> def'n right above it
    this.nss_t.SECKEYPrivateKey = ctypes.StructType(
      "SECKEYPrivateKey", [{ arena:        this.nss_t.PLArenaPool.ptr  },
                           { keyType:      this.nss_t.KeyType          },
                           { pkcs11Slot:   this.nss_t.PK11SlotInfo.ptr },
                           { pkcs11ID:     this.nss_t.CK_OBJECT_HANDLE },
                           { pkcs11IsTemp: this.nss_t.PRBool           },
                           { wincx:        ctypes.voidptr_t            },
                           { staticflags:  ctypes.unsigned_int         }]);

    // security/nss/lib/cryptohi/keythi.h#78
    // typedef struct SECKEYRSAPublicKeyStr --> def'n right above it
    this.nss_t.SECKEYRSAPublicKey = ctypes.StructType(
      "SECKEYRSAPublicKey", [{ arena:          this.nss_t.PLArenaPool.ptr },
                             { modulus:        this.nss_t.SECItem         },
                             { publicExponent: this.nss_t.SECItem         }]);

    // security/nss/lib/cryptohi/keythi.h#189
    // typedef struct SECKEYPublicKeyStr SECKEYPublicKey; --> def'n right above it
    this.nss_t.SECKEYPublicKey = ctypes.StructType(
      "SECKEYPublicKey", [{ arena:      this.nss_t.PLArenaPool.ptr    },
                          { keyType:    this.nss_t.KeyType            },
                          { pkcs11Slot: this.nss_t.PK11SlotInfo.ptr   },
                          { pkcs11ID:   this.nss_t.CK_OBJECT_HANDLE   },
                          { rsa:        this.nss_t.SECKEYRSAPublicKey } ]);

    // security/nss/lib/util/secoidt.h#52
    // typedef struct SECAlgorithmIDStr --> def'n right below it
    this.nss_t.SECAlgorithmID = ctypes.StructType(
      "SECAlgorithmID", [{ algorithm:  this.nss_t.SECItem },
                         { parameters: this.nss_t.SECItem }]);

    // security/nss/lib/certdb/certt.h#98
    // typedef struct CERTSubjectPublicKeyInfoStrA --> def'n on line 160
    this.nss_t.CERTSubjectPublicKeyInfo = ctypes.StructType(
      "CERTSubjectPublicKeyInfo", [{ arena:            this.nss_t.PLArenaPool.ptr },
                                   { algorithm:        this.nss_t.SECAlgorithmID  },
                                   { subjectPublicKey: this.nss_t.SECItem         }]);

    this.nss_t.PQGParams = ctypes.StructType(
      "PQGParams", [{ arena:        this.nss_t.PLArenaPool.ptr },
                         { prime:        this.nss_t.SECItem         },
                         { subPrime:     this.nss_t.SECItem         },
                         { base:         this.nss_t.SECItem         },]);

    this.nss_t.PQGVerify = ctypes.StructType(
      "PQGVerify", [{ arena: this.nss_t.PLArenaPool.ptr },
                    { counter: ctypes.unsigned_int},
                    { seed: this.nss_t.SECItem },
                    { h: this.nss_t.SECItem }]);


    /* XXX chrisk: this needs to be expanded to hold j and validationParms (RFC2459 7.3.2) */

    // security/nss/lib/util/pkcs11t.h
    this.nss.CKM_RSA_PKCS_KEY_PAIR_GEN = 0x0000;
    this.nss.CKM_DH_PKCS_KEY_PAIR_GEN  = 0x0020;
    this.nss.CKM_DSA_KEY_PAIR_GEN      = 0x0010;

    // security/nss/lib/softoken/secmodt.h
    this.nss.PK11_ATTR_SESSION   = 0x02;
    this.nss.PK11_ATTR_PUBLIC    = 0x08;
    this.nss.PK11_ATTR_SENSITIVE = 0x40;
    this.nss.PK11_ATTR_INSENSITIVE = 0x80;

    // security/nss/lib/pk11wrap/pk11pub.h#286
    // SECStatus PK11_GenerateRandom(unsigned char *data,int len);
    this.nss.PK11_GenerateRandom = nsslib.declare("PK11_GenerateRandom",
                                                  ctypes.default_abi, this.nss_t.SECStatus,
                                                  ctypes.unsigned_char.ptr, ctypes.int);
    // security/nss/lib/pk11wrap/pk11pub.h#74
    // PK11SlotInfo *PK11_GetInternalSlot(void);
    this.nss.PK11_GetInternalSlot = nsslib.declare("PK11_GetInternalSlot",
                                                   ctypes.default_abi, this.nss_t.PK11SlotInfo.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#73
    // PK11SlotInfo *PK11_GetInternalKeySlot(void);
    this.nss.PK11_GetInternalKeySlot = nsslib.declare("PK11_GetInternalKeySlot",
                                                      ctypes.default_abi, this.nss_t.PK11SlotInfo.ptr);

    this.nss.PK11_PrivDecryptPKCS1 = nsslib.declare("PK11_PrivDecryptPKCS1", 
                                                    ctypes.default_abi, this.nss_t.SECStatus, 
                                                    this.nss_t.SECKEYPrivateKey.ptr, 
                                                    ctypes.unsigned_char.ptr, ctypes.unsigned_int.ptr,
                                                    ctypes.unsigned_int, ctypes.unsigned_char.ptr,
                                                    ctypes.unsigned_int);

    /* The encrypt function that complements the above decrypt function. */
    this.nss.PK11_PubEncryptPKCS1 = nsslib.declare(
          "PK11_PubEncryptPKCS1", 
          ctypes.default_abi, this.nss_t.SECStatus, 
          this.nss_t.SECKEYPublicKey.ptr, 
          ctypes.unsigned_char.ptr, ctypes.unsigned_char.ptr,
          ctypes.unsigned_int, ctypes.voidptr_t
    );

    /* Generate PQGParams and PQGVerify structs.
     * Length of seed and length of h both equal length of P. 
     * All lengths are specified by "j", according to the table above.
     */
    this.nss.PK11_PQG_ParamGen = nsslib.declare(
          "PK11_PQG_ParamGen", 
          ctypes.default_abi, this.nss_t.SECStatus, 
          ctypes.unsigned_int,
          this.nss_t.PQGParams.ptr.ptr,
          this.nss_t.PQGVerify.ptr.ptr
    );

    // extern SECStatus PK11_PQG_GetPrimeFromParams(const PQGParams *params,
    //               SECItem * prime);
    this.nss.PK11_PQG_GetPrimeFromParams = nsslib.declare(
          "PK11_PQG_GetPrimeFromParams", 
          ctypes.default_abi, this.nss_t.SECStatus, 
          this.nss_t.PQGParams.ptr,
          this.nss_t.SECItem.ptr
    );

    this.nss.PK11_PubDecryptRaw = nsslib.declare(
          "PK11_PubDecryptRaw", 
          ctypes.default_abi, this.nss_t.SECStatus, 
          this.nss_t.SECKEYPrivateKey.ptr, 
          ctypes.unsigned_char.ptr, ctypes.unsigned_int.ptr,
          ctypes.unsigned_int, ctypes.unsigned_char.ptr,
          ctypes.unsigned_int
    );

    this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey = nsslib.declare("PK11_ImportDERPrivateKeyInfoAndReturnKey", 
          ctypes.default_abi, this.nss_t.SECStatus,
          this.nss_t.PK11SlotInfo.ptr, this.nss_t.SECItem.ptr,
          this.nss_t.SECItem.ptr, this.nss_t.SECItem.ptr,
          this.nss_t.PRBool, this.nss_t.PRBool, ctypes.int,  
          this.nss_t.SECKEYPrivateKey.ptr.ptr
    );

    // SIGNING API //////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////

    // security/nss/pk11wrap/pk11pub.h#682
    // int PK11_SignatureLength(SECKEYPrivateKey *key);
    this.nss.PK11_SignatureLen = nsslib.declare("PK11_SignatureLen",
                                                ctypes.default_abi,
                                                ctypes.int,
                                                this.nss_t.SECKEYPrivateKey.ptr);

    // security/nss/pk11wrap/pk11pub.h#684
    // SECStatus PK11_Sign(SECKEYPrivateKey *key, SECItem *sig, SECItem *hash);
    this.nss.PK11_Sign = nsslib.declare("PK11_Sign",
                                        ctypes.default_abi,
                                        this.nss_t.SECStatus,
                                        this.nss_t.SECKEYPrivateKey.ptr,
                                        this.nss_t.SECItem.ptr,
                                        this.nss_t.SECItem.ptr);

    // security/nss/pk11wrap/pk11pub.h#687
    // SECStatus PK11_Verify(SECKEYPublicKey *key, SECItem *sig, SECItem *hash, void *wincx);
    this.nss.PK11_Verify = nsslib.declare("PK11_Verify",
                                          ctypes.default_abi,
                                          this.nss_t.SECStatus,
                                          this.nss_t.SECKEYPublicKey.ptr,
                                          this.nss_t.SECItem.ptr,
                                          this.nss_t.SECItem.ptr,
                                          ctypes.voidptr_t);
    // END SIGNING API
    //////////////////////////////////////////////////////////////////////////

    // security/nss/lib/pk11wrap/pk11pub.h#507
    // SECKEYPrivateKey *PK11_GenerateKeyPairWithFlags(PK11SlotInfo *slot,
    //                                                 CK_MECHANISM_TYPE type, void *param, SECKEYPublicKey **pubk,
    //                                                 PK11AttrFlags attrFlags, void *wincx);
    this.nss.PK11_GenerateKeyPairWithFlags = nsslib.declare("PK11_GenerateKeyPairWithFlags",
                                                            ctypes.default_abi, this.nss_t.SECKEYPrivateKey.ptr,
                                                            this.nss_t.PK11SlotInfo.ptr, this.nss_t.CK_MECHANISM_TYPE, ctypes.voidptr_t,
                                                            this.nss_t.SECKEYPublicKey.ptr.ptr, this.nss_t.PK11AttrFlags, ctypes.voidptr_t);
    // security/nss/lib/pk11wrap/pk11pub.h#466
    // SECStatus PK11_SetPrivateKeyNickname(SECKEYPrivateKey *privKey, const char *nickname);
    this.nss.PK11_SetPrivateKeyNickname = nsslib.declare("PK11_SetPrivateKeyNickname",
                                                         ctypes.default_abi, this.nss_t.SECStatus,
                                                         this.nss_t.SECKEYPrivateKey.ptr, ctypes.char.ptr);
    // security/nss/lib/cryptohi/keyhi.h#159
    // SECItem* SECKEY_EncodeDERSubjectPublicKeyInfo(SECKEYPublicKey *pubk);
    this.nss.SECKEY_EncodeDERSubjectPublicKeyInfo = nsslib.declare("SECKEY_EncodeDERSubjectPublicKeyInfo",
                                                                   ctypes.default_abi, this.nss_t.SECItem.ptr,
                                                                   this.nss_t.SECKEYPublicKey.ptr);
    // security/nss/lib/cryptohi/keyhi.h#165
    // CERTSubjectPublicKeyInfo * SECKEY_DecodeDERSubjectPublicKeyInfo(SECItem *spkider);
    this.nss.SECKEY_DecodeDERSubjectPublicKeyInfo = nsslib.declare("SECKEY_DecodeDERSubjectPublicKeyInfo",
                                                                   ctypes.default_abi, this.nss_t.CERTSubjectPublicKeyInfo.ptr,
                                                                   this.nss_t.SECItem.ptr);
    // security/nss/lib/cryptohi/keyhi.h#179
    // SECKEYPublicKey * SECKEY_ExtractPublicKey(CERTSubjectPublicKeyInfo *);
    this.nss.SECKEY_ExtractPublicKey = nsslib.declare("SECKEY_ExtractPublicKey",
                                                      ctypes.default_abi, this.nss_t.SECKEYPublicKey.ptr,
                                                      this.nss_t.CERTSubjectPublicKeyInfo.ptr);

    // security/nss/lib/pk11wrap/pk11pub.h#70
    // void PK11_FreeSlot(PK11SlotInfo *slot);
    this.nss.PK11_FreeSlot = nsslib.declare("PK11_FreeSlot",
                                            ctypes.default_abi, ctypes.void_t,
                                            this.nss_t.PK11SlotInfo.ptr);
    // security/nss/lib/cryptohi/keyhi.h#193
    // extern void SECKEY_DestroyPublicKey(SECKEYPublicKey *key);
    this.nss.SECKEY_DestroyPublicKey = nsslib.declare("SECKEY_DestroyPublicKey",
                                                      ctypes.default_abi, ctypes.void_t,
                                                      this.nss_t.SECKEYPublicKey.ptr);
    // security/nss/lib/cryptohi/keyhi.h#186
    // extern void SECKEY_DestroyPrivateKey(SECKEYPrivateKey *key);
    this.nss.SECKEY_DestroyPrivateKey = nsslib.declare("SECKEY_DestroyPrivateKey",
                                                       ctypes.default_abi, ctypes.void_t,
                                                       this.nss_t.SECKEYPrivateKey.ptr);
    /*
     * Creates a PublicKey from its DER encoding.
     * Currently only supports RSA and DSA keys.
    */
    this.nss.SECKEY_PublicKeyStrengthInBits = nsslib.declare("SECKEY_PublicKeyStrengthInBits", 
                                                             ctypes.default_abi, ctypes.unsigned_int, 
                                                             this.nss_t.SECKEYPublicKey.ptr);
    // security/nss/lib/cryptohi/keyhi.h#58
    // extern void SECKEY_DestroySubjectPublicKeyInfo(CERTSubjectPublicKeyInfo *spki);
    this.nss.SECKEY_DestroySubjectPublicKeyInfo = nsslib.declare("SECKEY_DestroySubjectPublicKeyInfo",
                                                                 ctypes.default_abi, ctypes.void_t,
                                                                 this.nss_t.CERTSubjectPublicKeyInfo.ptr);

    // SECStatus PK11_ReadRawAttribute(PK11ObjectType type, void *object,
    // CK_ATTRIBUTE_TYPE attr, SECItem *item);
    this.nss.PK11_ReadRawAttribute = nsslib.declare("PK11_ReadRawAttribute",
                                                    ctypes.default_abi, this.nss_t.SECStatus, 
                                                    this.nss_t.SECStatus, ctypes.voidptr_t, 
                                                    this.nss_t.PK11AttrFlags, this.nss_t.SECItem.ptr);
  },

  sign : function _sign(aDerPrivKey, aDerPubKey, aHash) {
    this.log("sign() called");
    let privKey, slot, hash, sig;

    slot = this.nss.PK11_GetInternalSlot();
    if (slot.isNull())
      throw new Error("couldn't get internal slot");

    let derPrivKey = this.makeSECItem(aDerPrivKey, true);
    let derPubKey = this.makeSECItem(aDerPubKey, true);

    privKey = new this.nss_t.SECKEYPrivateKey.ptr();
    hash = this.makeSECItem(aHash, true);
    sig = this.makeSECItem("", false);

    var rv = this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, 
                    derPrivKey.address(), null, derPubKey.address(), false, 
                    true, (0x7fffffff >>> 0), privKey.address());

    if (privKey.isNull()) 
      throw new Error("sign error: Could not import DER private key");

    let sigLen = this.nss.PK11_SignatureLen(privKey);
    sig.len = sigLen;
    sig.data = new ctypes.ArrayType(ctypes.unsigned_char, sigLen)();

    let status = this.nss.PK11_Sign(privKey, sig.address(), hash.address());
    if (status == -1)
      throw new Error("Could not sign message");

    return this.encodeBase64(sig.data, sig.len);
  },

  verify : function _verify(aDerPubKey, aSignature, aHash) {
    this.log("verify() called");
    let derPubKey = this.makeSECItem(aDerPubKey, true);
    let pubKeyInfo = this.nss.SECKEY_DecodeDERSubjectPublicKeyInfo(derPubKey.address());
    if (pubKeyInfo.isNull())
      throw new Error("SECKEY_DecodeDERSubjectPublicKeyInfo failed");

    let pubKey = this.nss.SECKEY_ExtractPublicKey(pubKeyInfo);

    if (pubKey.isNull())
      throw new Error("SECKEY_ExtractPublicKey failed");

    let sig = this.makeSECItem(aSignature, false);
    let hash = this.makeSECItem(aHash, false);

    let status =
      this.nss.PK11_Verify(pubKey, sig.address(), hash.address(), null);

    this.log("verify return " + status); 

    if (status == -1) {
      return false;
    }
    return true;
  },

  generateKeypair : function(keyType, keypairBits, out_fields) {

    this.log("generateKeypair() called. keytype("+ keyType + ") keybits("+ keypairBits + ")");

    let pubKey, privKey, slot;
    try {
      // Attributes for the private key. We're just going to wrap and extract the
      // value, so they're not critical. The _PUBLIC attribute just indicates the
      // object can be accessed without being logged into the token.

      let params, genType, rc;
      switch(keyType) {
        case PUB_ALGO.RSA:
          let rsaParams = new this.nss_t.PK11RSAGenParams();
          rsaParams.keySizeInBits = keypairBits; // 1024, 2048, etc.
          rsaParams.pe = 65537;                  // public exponent.
          params = rsaParams.address();
          genType = this.nss.CKM_RSA_PKCS_KEY_PAIR_GEN;
          break;

        case PUB_ALGO.DSA:
          var pqgparams = new this.nss_t.PQGParams.ptr();
          var pqgverify = new this.nss_t.PQGVerify.ptr();
          rc = this.nss.PK11_PQG_ParamGen(8, pqgparams.address(), pqgverify.address());
          params = pqgparams;
          genType = this.nss.CKM_DSA_KEY_PAIR_GEN;
          break;

        case PUB_ALGO.ELGAMAL_E:
          var dhParams = new this.nss_t.SECKEYDHParams();
          var pqgparams = new this.nss_t.PQGParams.ptr();
          var pqgverify = new this.nss_t.PQGVerify.ptr();
          rc = this.nss.PK11_PQG_ParamGen(8, pqgparams.address(), pqgverify.address());
          var prime = this.makeSECItem("", false);
          rc = this.nss.PK11_PQG_GetPrimeFromParams(pqgparams, prime.address());
          dhParams.base = this.makeSECItem(String.fromCharCode(5), false);
          dhParams.prime = prime;
          params = dhParams.address();
          genType = this.nss.CKM_DH_PKCS_KEY_PAIR_GEN;
          break;

        default:
          throw new Error("Unkown key type algo: " + keyType);
      }

      slot = this.nss.PK11_GetInternalSlot();
      if (slot.isNull())
        throw new Error("couldn't get internal slot");

      let attrFlags = (this.nss.PK11_ATTR_SESSION | this.nss.PK11_ATTR_PUBLIC | this.nss.PK11_ATTR_INSENSITIVE);
      pubKey  = new this.nss_t.SECKEYPublicKey.ptr();
      // Generate the keypair.
      privKey = this.nss.PK11_GenerateKeyPairWithFlags(slot,
                                                       genType,
                                                       params,
                                                       pubKey.address(),
                                                       attrFlags, null);
      if (privKey.isNull())
        throw new Error("keypair generation failed");

      let s = this.nss.PK11_SetPrivateKeyNickname(privKey, "Weave User PrivKey");
      if (s)
        throw new Error("key nickname failed");

      try {

        // Use a buffer to hold the wrapped key. NSS says about 1200 bytes for
        // a 2048-bit RSA key, so a 4096 byte buffer should be plenty.

        var CKA_MODULUS          = 0x00000120;
        var CKA_MODULUS_BITS     = 0x00000121;
        var CKA_PUBLIC_EXPONENT  = 0x00000122;
        var CKA_PRIVATE_EXPONENT = 0x00000123;
        var CKA_PRIME_1          = 0x00000124;
        var CKA_PRIME_2          = 0x00000125;
        var CKA_EXPONENT_1       = 0x00000126;
        var CKA_EXPONENT_2       = 0x00000127;
        var CKA_COEFFICIENT      = 0x00000128;
        var CKA_PRIME            = 0x00000130;
        var CKA_SUBPRIME         = 0x00000131;
        var CKA_BASE             = 0x00000132;
        var CKA_VALUE            = 0x00000011;
        var CKA_DERIVE           = 0x0000010C;
        var CKA_NETSCAPE_DB      = 0xD5A0DB00;

        function getAttribute(self, privKey, attrtype) {
          // Use a buffer to hold the wrapped key. NSS says about 1200 bytes for
          // a 2048-bit RSA key, so a 4096 byte buffer should be plenty.
          let keyData = new ctypes.ArrayType(ctypes.unsigned_char, 4096)();
          let outData = new self.nss_t.SECItem(self.nss.SIBUFFER, keyData, keyData.length);
          let rc = self.nss.PK11_ReadRawAttribute(1, privKey, attrtype, outData.address());
          let intData = ctypes.cast(outData.data, ctypes.uint8_t.array(outData.len).ptr).contents;
          let expanded ="";
          for (let i = 0; i < outData.len; i++)
            expanded += String.fromCharCode(intData[i]);
          return btoa(expanded);
        }

        switch(keyType) {
          case PUB_ALGO.RSA: 
          out_fields.n = getAttribute(this, privKey, CKA_MODULUS);
          out_fields.e = getAttribute(this, privKey, CKA_PUBLIC_EXPONENT);
          out_fields.d = getAttribute(this, privKey, CKA_PRIVATE_EXPONENT);
          out_fields.q = getAttribute(this, privKey, CKA_PRIME_1)  
          out_fields.p = getAttribute(this, privKey, CKA_PRIME_2) 
          out_fields.u = getAttribute(this, privKey, CKA_COEFFICIENT)
          break;
          case PUB_ALGO.ELGAMAL_E: //D-H
          out_fields.p = getAttribute(this, privKey, CKA_PRIME);
          out_fields.x = getAttribute(this, privKey, CKA_VALUE);
          out_fields.g = getAttribute(this, privKey, CKA_BASE);
          out_fields.y = getAttribute(this, privKey, CKA_NETSCAPE_DB);
          break;
          case PUB_ALGO.DSA:
          out_fields.p = getAttribute(this, privKey, CKA_PRIME);
          out_fields.q = getAttribute(this, privKey, CKA_SUBPRIME);
          out_fields.g = getAttribute(this, privKey, CKA_BASE);
          out_fields.x = getAttribute(this, privKey, CKA_VALUE);
          out_fields.y = getAttribute(this, privKey, CKA_NETSCAPE_DB);
          break;
          default:
          throw new Error("Unkown key type algo: " + keyType);
          break;
        }
      } catch (e) {
        this.log("generateKeypair: failed: " + e + e.lineNumber);
        throw e;
      } finally {
        if (pubKey && !pubKey.isNull())
          this.nss.SECKEY_DestroyPublicKey(pubKey);
        if (privKey && !privKey.isNull())
          this.nss.SECKEY_DestroyPrivateKey(privKey);
        if (slot && !slot.isNull())
          this.nss.PK11_FreeSlot(slot);
      }
    } catch (e) {
      dump(e);
    }
  },

  generateRandomBytes : function(byteCount) {
    this.log("generateRandomBytes() called");

    // Temporary buffer to hold the generated data.
    let scratch = new ctypes.ArrayType(ctypes.unsigned_char, byteCount)();
    if (this.nss.PK11_GenerateRandom(scratch, byteCount))
      throw new Error("PK11_GenrateRandom failed");

    return this.encodeBase64(scratch.address(), scratch.length);
  },

  encrypt : function(aHash, aDerPubKey) {
    this.log("encrypt() called");

    // Step 1. Get rid of the base64 encoding on the inputs.
    let derPubKey = this.makeSECItem(aDerPubKey, true);
    let hash = atob(aHash);
    let slot, pubKeyInfo, pubKey;

    try {
      slot = this.nss.PK11_GetInternalSlot();
      if (slot.isNull())
        throw new Error("couldn't get internal slot");

      pubKeyInfo = this.nss.SECKEY_DecodeDERSubjectPublicKeyInfo(derPubKey.address());
      if (pubKeyInfo.isNull())
        throw new Error("SECKEY_DecodeDERSubjectPublicKeyInfo failed");

      pubKey = this.nss.SECKEY_ExtractPublicKey(pubKeyInfo);
      if (pubKey.isNull())
        throw new Error("SECKEY_ExtractPublicKey failed");

      let byteLen = this.nss.SECKEY_PublicKeyStrengthInBits(pubKey) / 8; 
      
      let inputData = new ctypes.ArrayType(ctypes.unsigned_char, hash.length)(); 
      this.byteCompress(hash, inputData);

      let outputData = new ctypes.ArrayType(ctypes.unsigned_char, byteLen)(); 

      let s = this.nss.PK11_PubEncryptPKCS1(pubKey, outputData, inputData, hash.length, null); 

      if (s)
        throw new Error("PK11_PubEncryptPKCS1 failed");

      return this.encodeBase64(outputData.address(), outputData.length);

    } catch (e) {
      this.log("encrypt: failed: " + e);
      throw e;
    } finally {
      if (pubKey && !pubKey.isNull())
        this.nss.SECKEY_DestroyPublicKey(pubKey);
      if (pubKeyInfo && !pubKeyInfo.isNull())
        this.nss.SECKEY_DestroySubjectPublicKeyInfo(pubKeyInfo);
      if (slot && !slot.isNull())
        this.nss.PK11_FreeSlot(slot);
    }
  },

  decrypt : function(aHash, aDerPrivKey) {
    this.log("decrypt() called");
    // Step 1. Get rid of the base64 encoding on the inputs.
    let derPrivKey = this.makeSECItem(aDerPrivKey, true);
    let slot, privKey;
    try {

      slot = this.nss.PK11_GetInternalSlot();
      if (slot.isNull())
        throw new Error("couldn't get internal slot");

      let privKey = new this.nss_t.SECKEYPrivateKey.ptr();

      var rv = this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, derPrivKey.address(),
                                                                 null, null, false, true, 
                                                                 (0x7fffffff >>> 0), privKey.address());
      if (privKey.isNull())
        throw new Error("Import DER private key failed");

      let input = atob(aHash);
      let byteLen = input.length;

      let inputData = new ctypes.ArrayType(ctypes.unsigned_char, byteLen)(); this.byteCompress(input, inputData);
      let outputData = new ctypes.ArrayType(ctypes.unsigned_char, byteLen)(); 
      let outputLen = new ctypes.unsigned;

      rv = this.nss.PK11_PrivDecryptPKCS1(privKey, outputData, 
                                          outputLen.address(), byteLen, 
                                          inputData, byteLen);

      return this.encodeBase64(outputData.address(), outputData.length);

    } catch (e) {
      this.log("decrypt: failed: " + e);
      throw e;
    } finally {
      if (privKey && !privKey.isNull())
        this.nss.SECKEY_DestroyPrivateKey(privKey);
      if (slot && !slot.isNull())
        this.nss.PK11_FreeSlot(slot);
    }
  },


  //
  // Utility functions
  //


  // Compress a JS string (2-byte chars) into a normal C string (1-byte chars)
  // EG, for "ABC",  0x0041, 0x0042, 0x0043 --> 0x41, 0x42, 0x43
  byteCompress : function (jsString, charArray) {
    let intArray = ctypes.cast(charArray, ctypes.uint8_t.array(charArray.length));
    for (let i = 0; i < jsString.length; i++) {
      intArray[i] = jsString.charCodeAt(i) % 256; // convert to bytes
    }

  },

  // Expand a normal C string (1-byte chars) into a JS string (2-byte chars)
  // EG, for "ABC",  0x41, 0x42, 0x43 --> 0x0041, 0x0042, 0x0043
  byteExpand : function (charArray) {
    let expanded = "";
    let len = charArray.length;
    let intData = ctypes.cast(charArray, ctypes.uint8_t.array(len));
    for (let i = 0; i < len; i++)
      expanded += String.fromCharCode(intData[i]);

    return expanded;
  },

  encodeBase64 : function (data, len) {
    // Byte-expand the buffer, so we can treat it as a UCS-2 string
    // consisting of u0000 - u00FF.
    let expanded = "";
    let intData = ctypes.cast(data, ctypes.uint8_t.array(len).ptr).contents;
    for (let i = 0; i < len; i++)
      expanded += String.fromCharCode(intData[i]);

    return btoa(expanded);
  },

  makeSECItem : function(input, isEncoded) {
    if (isEncoded)
      input = atob(input);

    let outputData = new ctypes.ArrayType(ctypes.unsigned_char, input.length)(); 
    this.byteCompress(input, outputData);

    return new this.nss_t.SECItem(this.nss.SIBUFFER, outputData, outputData.length);
  },
};


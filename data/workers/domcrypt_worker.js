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
 * NOTE
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
 */

var DEBUG = true;

const misc = { 
  atob : function(arr) {
    var d = "";

    for (var i = 0; i<arr.length; i++)
      d += String.fromCharCode(arr[i]);
    return d;
  }
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
   * Create a KeyPair for general purpose PKI
   *
   * @param string aPassphrase
   *        The passphrase used to generate a keypair
   * @returns object
   *          The object returned looks like:
   *          { action:  "keypairGenerated",
   *            pubKey:  <PUBLIC KEY>,
   *            privKey: <PRIVATE KEY>,
   *            salt:    <SALT>,
   *            iv:      <INITIALIZATION VECTOR>,
   *            created: <DATE CREATED>
   *          }
   */
  generateKeypair: function WCW_generateKeypair(keyType, keypairBits)
  {
    var pubOut = {};
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
   * @param string aPlainText
   *        The plain text that will be encrypted
   * @param string aPublicKey
   *        The recipient's base64 encoded public key
   * @returns Object
   *          A 'message' object:
   *          { content:    <ENCRYPTED_STRING>,
   *            pubKey:     <RECIPIENT PUB_KEY>,
   *            wrappedKey: <WRAPPED SYM_KEY>,
   *            iv:         <INITIALIZATION VECTOR>
   *          }
   */
  encrypt: function WCW_encrypt(aPlainText, aPublicKey)
  {
    if (!aPlainText && !aPublicKey) {
      throw new Error("Missing Arguments: aPlainText and aPublicKey are required");
    }
    try {
      var wrappedKey = WeaveCrypto.wrapSymmetricKey(aPlainText, aPublicKey);
      return  wrappedKey;
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
   * @param object aCipherMessage
   *         An object literal much like:
   *         { content:    <ENCRYPTED_STRING>,
   *           pubKey:     <RECIPIENT PUB_KEY>,
   *           wrappedKey: <WRAPPED SYM_KEY>,
   *           iv:         <INITIALIZATION VECTOR>
   *         }
   * @param string aPassphrase
   *        The plain text passphrase used when the private key was generated
   * @param string aPrivateKey
   *        The base64 encoded private key string
   * @param string aSalt
   *        The salt used when the key pair was generated
   * @param string aIV
   *        The IV used when the keypair was generated
   * @returns string
   *          The decrypted message
   */
  decrypt:
  function WCW_decrypt(wrappedKey, aPrivateKey)
  {
    try {
      var decrypted_padded64 = WeaveCrypto.unwrapSymmetricKey(wrappedKey, aPrivateKey);
      return decrypted_padded64;
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
      throw(ex);
    }
    finally {
      // get rid of the passphrase
      //delete aPassphrase;
      //delete aPrivateKey;
    }
  },

  /**
   * Cryptographically sign a message
   *
   * @param string aHash
   *        A SHA256 hash of the plain text message
   * @param string aPassphrase
   *        The sender's passphrase used to generate her keypair
   * @param string aPrivateKey
   *        The sender's base64 encoded private key
   * @param string aIV
   *        The IV used to generate the sender's keypair
   * @param string aSalt
   *        The salt used to generate the sender's keypair
   * @returns string
   *          A base64 encoded signature string
   */
  sign: function WCW_sign(aHash, aPrivateKey, aPublicKey)
  {
    var signature;
    try {
      signature = WeaveCrypto.sign(aPrivateKey, aPublicKey, aHash);
      return signature;
    }
    catch (ex) {
      throw ex;
    }
    finally {
      //delete aPrivateKey;
      //delete aPassphrase;
      //delete aIV;
      //delete aSalt;
    }
  },

  /**
   * Verify a signature was created by the sender
   *
   * @param string aHash
   *        A SHA256 hash of the decrypted message
   * @param string aSignature
   *        A base64 encoded signature string
   * @param string aPublicKey
   *        The sender's base 64 encoded public key
   * @returns boolean
   */
  verify: function WCW_verify(aHash, aSignature, aPublicKey)
  {
    try {
      let results = WeaveCrypto.verify(aPublicKey, aSignature, aHash);

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
  debug      : DEBUG,
  nss        : null,
  nss_t      : null,

  log : function (message) {
    if (!DEBUG)
      return;
    dump("WeaveCrypto: " + message + "\n");
  },

  shutdown : function WC_shutdown()
  {
    this.log("closing nsslib");
    this.nsslib.close();
  },

  fullPathToLib: null,

  initNSS : function WC_initNSS(aNSSPath) {
    // Open the NSS library.
    this.fullPathToLib = aNSSPath;
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
    // security/nss/lib/softoken/secmodt.h#359
    // typedef enum PK11Origin
    this.nss_t.PK11Origin = ctypes.int;
    // PK11Origin enum values...
    this.nss.PK11_OriginUnwrap = 4;
    // security/nss/lib/softoken/secmodt.h#61
    // typedef struct PK11SymKeyStr PK11SymKey; (defined in secmodti.h)
    this.nss_t.PK11SymKey = ctypes.void_t;
    // security/nss/lib/util/secoidt.h#454
    // typedef enum
    this.nss_t.SECOidTag = ctypes.int;
    // security/nss/lib/util/seccomon.h#64
    // typedef enum
    this.nss_t.SECItemType = ctypes.int;
    // SECItemType enum values...
    this.nss.SIBUFFER = 0;
    // security/nss/lib/softoken/secmodt.h#62 (defined in secmodti.h)
    // typedef struct PK11ContextStr PK11Context;
    this.nss_t.PK11Context = ctypes.void_t;
    // Needed for SECKEYPrivateKey struct def'n, but I don't think we need to actually access it.
    this.nss_t.PLArenaPool = ctypes.void_t;
    // security/nss/lib/cryptohi/keythi.h#45
    // typedef enum
    
    this.nss_t.KeyType = ctypes.int;
    // security/nss/lib/softoken/secmodt.h#201
    // typedef PRUint32 PK11AttrFlags;
    this.nss_t.PK11AttrFlags = ctypes.unsigned_int;
    // security/nss/lib/util/secoidt.h#454
    // typedef enum
    this.nss_t.SECOidTag = ctypes.int;
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

    //./lib/cryptohi/keythi.h#106
    ///*
    //** DSA Public Key and related structures
    //*/
    //
    //struct SECKEYPQGParamsStr {
    //    PLArenaPool *arena;
    //    SECItem prime;    /* p */
    //    SECItem subPrime; /* q */
    //    SECItem base;     /* g */
    //    /* XXX chrisk: this needs to be expanded to hold j and validationParms (RFC2459 7.3.2) */
    //};
    this.nss_t.SECKEYPQGParams = ctypes.StructType(
      "SECKEYPQGParams", [{ arena:        this.nss_t.PLArenaPool.ptr },
                         { prime:        this.nss_t.SECItem         },
                         { subPrime:     this.nss_t.SECItem         },
                         { base:         this.nss_t.SECItem         },]);



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
    // XXX: "rsa" et al into a union here!
    // { dsa: SECKEYDSAPublicKey },
    // { dh:  SECKEYDHPublicKey },
    // { kea: SECKEYKEAPublicKey },
    // { fortezza: SECKEYFortezzaPublicKey },
    // { ec:  SECKEYECPublicKey } ]);
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
    /*
    ** A PKCS#8 private key info object
    *  security/nss/lib/softoken/secmodt.h
    */
    this.nss_t.SECKEYEncryptedPrivateKeyInfo = ctypes.StructType(
      "SECKEYEncryptedPrivateKeyInfo", [{ arena : this.nss_t.PLArenaPool.ptr },
                                        { algorithm : this.nss_t.SECAlgorithmID },
                                        { encryptedData : this.nss_t.SECItem }]);

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
    this.nss.CKK_RSA = 0x0;
    this.nss.CKM_RSA_PKCS_KEY_PAIR_GEN = 0x0000;
    this.nss.CKM_AES_KEY_GEN           = 0x1080;
//#define CKM_DH_PKCS_KEY_PAIR_GEN       0x00000020
//#define CKM_DH_PKCS_DERIVE             0x00000021
    this.nss.CKM_DH_PKCS_KEY_PAIR_GEN  = 0x0020;
    this.nss.CKM_DH_PKCS_DERIVE        = 0x0021;
    this.nss.CKM_DSA_KEY_PAIR_GEN      = 0x0010;
    this.nss.CKA_ENCRYPT = 0x0104;
    this.nss.CKA_DECRYPT = 0x0105;
    this.nss.CKA_UNWRAP  = 0x0107;

    // security/nss/lib/softoken/secmodt.h
    this.nss.PK11_ATTR_SESSION   = 0x02;
    this.nss.PK11_ATTR_PUBLIC    = 0x08;
    this.nss.PK11_ATTR_SENSITIVE = 0x40;
    this.nss.PK11_ATTR_INSENSITIVE = 0x80;

    this.nss.PK11_ATTR_PUBLIC    = 0x08;

    // security/nss/lib/util/secoidt.h
    this.nss.SEC_OID_HMAC_SHA1            = 294;
    this.nss.SEC_OID_PKCS1_RSA_ENCRYPTION = 16;


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

    this.nss.PK11_PrivDecryptPKCS1 = nsslib.declare(
          "PK11_PrivDecryptPKCS1", 
          ctypes.default_abi, this.nss_t.SECStatus, 
          this.nss_t.SECKEYPrivateKey.ptr, 
          ctypes.unsigned_char.ptr, ctypes.unsigned_int.ptr,
          ctypes.unsigned_int, ctypes.unsigned_char.ptr,
          ctypes.unsigned_int
    );
    /* The encrypt function that complements the above decrypt function. */
    this.nss.PK11_PubEncryptPKCS1 = nsslib.declare(
          "PK11_PubEncryptPKCS1", 
          ctypes.default_abi, this.nss_t.SECStatus, 
          this.nss_t.SECKEYPublicKey.ptr, 
          ctypes.unsigned_char.ptr, ctypes.unsigned_char.ptr,
          ctypes.unsigned_int, ctypes.voidptr_t
    );
    /* The encrypt function that complements the above decrypt function. */
    this.nss.PK11_PubEncryptRaw = nsslib.declare(
          "PK11_PubEncryptRaw", 
          ctypes.default_abi, this.nss_t.SECStatus, 
          this.nss_t.SECKEYPublicKey.ptr, 
          ctypes.unsigned_char.ptr, ctypes.unsigned_char.ptr,
          ctypes.unsigned_int, ctypes.voidptr_t
    );
          /* The encrypt function that complements the above decrypt function. */

    //    /* Generate PQGParams and PQGVerify structs.
    //     * Length of seed and length of h both equal length of P. 
    //     * All lengths are specified by "j", according to the table above.
    //     */
    //    extern SECStatus
    //    PK11_PQG_ParamGen(unsigned int j, PQGParams **pParams, PQGVerify **pVfy)
    //    {
    //        return PK11_PQG_ParamGenSeedLen(j, 0, pParams, pVfy);
    //    }
    this.nss.PK11_PQG_ParamGen = nsslib.declare(
          "PK11_PQG_ParamGen", 
          ctypes.default_abi, this.nss_t.SECStatus, 
          ctypes.unsigned_int,
          this.nss_t.PQGParams.ptr.ptr,
          this.nss_t.PQGVerify.ptr.ptr
    );
//    extern SECStatus PK11_PQG_GetPrimeFromParams(const PQGParams *params,
//                  SECItem * prime);
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
    // security/nss/lib/pk11wrap/pk11pub.h#328
    // PK11SymKey *PK11_KeyGen(PK11SlotInfo *slot,CK_MECHANISM_TYPE type, SECItem *param, int keySize,void *wincx);
    this.nss.PK11_KeyGen = nsslib.declare("PK11_KeyGen",
                                          ctypes.default_abi, this.nss_t.PK11SymKey.ptr,
                                          this.nss_t.PK11SlotInfo.ptr, this.nss_t.CK_MECHANISM_TYPE,
                                          this.nss_t.SECItem.ptr, ctypes.int, ctypes.voidptr_t);
    this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey = nsslib.declare("PK11_ImportDERPrivateKeyInfoAndReturnKey", ctypes.default_abi, this.nss_t.SECStatus,
    this.nss_t.PK11SlotInfo.ptr, this.nss_t.SECItem.ptr,
    this.nss_t.SECItem.ptr,this.nss_t.SECItem.ptr,
    this.nss_t.PRBool,this.nss_t.PRBool, ctypes.int,  
    this.nss_t.SECKEYPrivateKey.ptr.ptr
    );

    this.nss.PK11_GetPQGParamsFromPrivateKey = nsslib.declare("PK11_GetPQGParamsFromPrivateKey", ctypes.default_abi, this.nss_t.SECKEYPQGParams.ptr, this.nss_t.SECKEYPrivateKey.ptr); 

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

    //./lib/pk11wrap/pk11akey.c
    this.nss.PK11_ExportEncryptedPrivKeyInfo = nsslib.declare("PK11_ExportEncryptedPrivKeyInfo", ctypes.default_abi, this.nss_t.SECKEYEncryptedPrivateKeyInfo, this.nss_t.PK11SlotInfo.ptr, this.nss_t.SECOidTag, this.nss_t.SECItem.ptr,this.nss_t.SECKEYPrivateKey.ptr, ctypes.int, ctypes.voidptr_t);


    
    //SECKEYEncryptedPrivateKeyInfo *
    // security/nss/lib/pk11wrap/pk11pub.h#477
    // SECStatus PK11_ExtractKeyValue(PK11SymKey *symKey);
    this.nss.PK11_ExtractKeyValue = nsslib.declare("PK11_ExtractKeyValue",
                                                   ctypes.default_abi, this.nss_t.SECStatus,
                                                   this.nss_t.PK11SymKey.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#478
    // SECItem * PK11_GetKeyData(PK11SymKey *symKey);
    this.nss.PK11_GetKeyData = nsslib.declare("PK11_GetKeyData",
                                              ctypes.default_abi, this.nss_t.SECItem.ptr,
                                              this.nss_t.PK11SymKey.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#278
    // CK_MECHANISM_TYPE PK11_AlgtagToMechanism(SECOidTag algTag);
    this.nss.PK11_AlgtagToMechanism = nsslib.declare("PK11_AlgtagToMechanism",
                                                     ctypes.default_abi, this.nss_t.CK_MECHANISM_TYPE,
                                                     this.nss_t.SECOidTag);
    // security/nss/lib/pk11wrap/pk11pub.h#270
    // int PK11_GetIVLength(CK_MECHANISM_TYPE type);
    this.nss.PK11_GetIVLength = nsslib.declare("PK11_GetIVLength",
                                               ctypes.default_abi, ctypes.int,
                                               this.nss_t.CK_MECHANISM_TYPE);
    // security/nss/lib/pk11wrap/pk11pub.h#269
    // int PK11_GetBlockSize(CK_MECHANISM_TYPE type,SECItem *params);
    this.nss.PK11_GetBlockSize = nsslib.declare("PK11_GetBlockSize",
                                                ctypes.default_abi, ctypes.int,
                                                this.nss_t.CK_MECHANISM_TYPE, this.nss_t.SECItem.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#293
    // CK_MECHANISM_TYPE PK11_GetPadMechanism(CK_MECHANISM_TYPE);
    this.nss.PK11_GetPadMechanism = nsslib.declare("PK11_GetPadMechanism",
                                                   ctypes.default_abi, this.nss_t.CK_MECHANISM_TYPE,
                                                   this.nss_t.CK_MECHANISM_TYPE);
    // security/nss/lib/pk11wrap/pk11pub.h#271
    // SECItem *PK11_ParamFromIV(CK_MECHANISM_TYPE type,SECItem *iv);
    this.nss.PK11_ParamFromIV = nsslib.declare("PK11_ParamFromIV",
                                               ctypes.default_abi, this.nss_t.SECItem.ptr,
                                               this.nss_t.CK_MECHANISM_TYPE, this.nss_t.SECItem.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#301
    // PK11SymKey *PK11_ImportSymKey(PK11SlotInfo *slot, CK_MECHANISM_TYPE type, PK11Origin origin,
    //                               CK_ATTRIBUTE_TYPE operation, SECItem *key, void *wincx);
    this.nss.PK11_ImportSymKey = nsslib.declare("PK11_ImportSymKey",
                                                ctypes.default_abi, this.nss_t.PK11SymKey.ptr,
                                                this.nss_t.PK11SlotInfo.ptr, this.nss_t.CK_MECHANISM_TYPE, this.nss_t.PK11Origin,
                                                this.nss_t.CK_ATTRIBUTE_TYPE, this.nss_t.SECItem.ptr, ctypes.voidptr_t);
    // security/nss/lib/pk11wrap/pk11pub.h#672
    // PK11Context *PK11_CreateContextBySymKey(CK_MECHANISM_TYPE type, CK_ATTRIBUTE_TYPE operation,
    //                                         PK11SymKey *symKey, SECItem *param);
    this.nss.PK11_CreateContextBySymKey = nsslib.declare("PK11_CreateContextBySymKey",
                                                         ctypes.default_abi, this.nss_t.PK11Context.ptr,
                                                         this.nss_t.CK_MECHANISM_TYPE, this.nss_t.CK_ATTRIBUTE_TYPE,
                                                         this.nss_t.PK11SymKey.ptr, this.nss_t.SECItem.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#685
    // SECStatus PK11_CipherOp(PK11Context *context, unsigned char *out
    //                         int *outlen, int maxout, unsigned char *in, int inlen);
    this.nss.PK11_CipherOp = nsslib.declare("PK11_CipherOp",
                                            ctypes.default_abi, this.nss_t.SECStatus,
                                            this.nss_t.PK11Context.ptr, ctypes.unsigned_char.ptr,
                                            ctypes.int.ptr, ctypes.int, ctypes.unsigned_char.ptr, ctypes.int);
    // security/nss/lib/pk11wrap/pk11pub.h#688
    // SECStatus PK11_DigestFinal(PK11Context *context, unsigned char *data,
    //                            unsigned int *outLen, unsigned int length);
    this.nss.PK11_DigestFinal = nsslib.declare("PK11_DigestFinal",
                                               ctypes.default_abi, this.nss_t.SECStatus,
                                               this.nss_t.PK11Context.ptr, ctypes.unsigned_char.ptr,
                                               ctypes.unsigned_int.ptr, ctypes.unsigned_int);
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
    // security/nss/lib/pk11wrap/pk11pub.h#731
    // SECAlgorithmID * PK11_CreatePBEV2AlgorithmID(SECOidTag pbeAlgTag, SECOidTag cipherAlgTag,
    //                                              SECOidTag prfAlgTag, int keyLength, int iteration,
    //                                              SECItem *salt);
    this.nss.PK11_CreatePBEV2AlgorithmID = nsslib.declare("PK11_CreatePBEV2AlgorithmID",
                                                          ctypes.default_abi, this.nss_t.SECAlgorithmID.ptr,
                                                          this.nss_t.SECOidTag, this.nss_t.SECOidTag, this.nss_t.SECOidTag,
                                                          ctypes.int, ctypes.int, this.nss_t.SECItem.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#736
    // PK11SymKey * PK11_PBEKeyGen(PK11SlotInfo *slot, SECAlgorithmID *algid,  SECItem *pwitem, PRBool faulty3DES, void *wincx);
    this.nss.PK11_PBEKeyGen = nsslib.declare("PK11_PBEKeyGen",
                                             ctypes.default_abi, this.nss_t.PK11SymKey.ptr,
                                             this.nss_t.PK11SlotInfo.ptr, this.nss_t.SECAlgorithmID.ptr,
                                             this.nss_t.SECItem.ptr, this.nss_t.PRBool, ctypes.voidptr_t);
    // security/nss/lib/pk11wrap/pk11pub.h#574
    // SECStatus PK11_WrapPrivKey(PK11SlotInfo *slot, PK11SymKey *wrappingKey,
    //                            SECKEYPrivateKey *privKey, CK_MECHANISM_TYPE wrapType,
    //                            SECItem *param, SECItem *wrappedKey, void *wincx);
    this.nss.PK11_WrapPrivKey = nsslib.declare("PK11_WrapPrivKey",
                                               ctypes.default_abi, this.nss_t.SECStatus,
                                               this.nss_t.PK11SlotInfo.ptr, this.nss_t.PK11SymKey.ptr,
                                               this.nss_t.SECKEYPrivateKey.ptr, this.nss_t.CK_MECHANISM_TYPE,
                                               this.nss_t.SECItem.ptr, this.nss_t.SECItem.ptr, ctypes.voidptr_t);
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
//    this.nss.SECKEY_ExtractPublicKey = nsslib.declare("SECKEY_ExtractPublicKey",
//                                                      ctypes.default_abi, this.nss_t.SECKEYPublicKey.ptr,
//                                                      this.nss_t.CERTSubjectPublicKeyInfo.ptr, ctypes.int);
    this.nss.SECKEY_ExtractPublicKey = nsslib.declare("SECKEY_ExtractPublicKey",
                                                      ctypes.default_abi, this.nss_t.SECKEYPublicKey.ptr,
                                                      this.nss_t.CERTSubjectPublicKeyInfo.ptr);
    /*
     * Creates a PublicKey from its DER encoding.
     * Currently only supports RSA and DSA keys.
    */
    this.nss.SECKEY_ImportDERPublicKey = nsslib.declare("SECKEY_ImportDERPublicKey",
                                                        ctypes.default_abi, this.nss_t.SECKEYPublicKey.ptr,
                                                        this.nss_t.SECItem.ptr, this.nss_t.CK_KEY_TYPE);

    // security/nss/lib/pk11wrap/pk11pub.h#377
    // SECStatus PK11_PubWrapSymKey(CK_MECHANISM_TYPE type, SECKEYPublicKey *pubKey,
    //                              PK11SymKey *symKey, SECItem *wrappedKey);
    this.nss.PK11_PubWrapSymKey = nsslib.declare("PK11_PubWrapSymKey",
                                                 ctypes.default_abi, this.nss_t.SECStatus,
                                                 this.nss_t.CK_MECHANISM_TYPE, this.nss_t.SECKEYPublicKey.ptr,
                                                 this.nss_t.PK11SymKey.ptr, this.nss_t.SECItem.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#568
    // SECKEYPrivateKey *PK11_UnwrapPrivKey(PK11SlotInfo *slot,
    //                 PK11SymKey *wrappingKey, CK_MECHANISM_TYPE wrapType,
    //                 SECItem *param, SECItem *wrappedKey, SECItem *label,
    //                 SECItem *publicValue, PRBool token, PRBool sensitive,
    //                 CK_KEY_TYPE keyType, CK_ATTRIBUTE_TYPE *usage, int usageCount,
    //                 void *wincx);
    this.nss.PK11_UnwrapPrivKey = nsslib.declare("PK11_UnwrapPrivKey",
                                                 ctypes.default_abi, this.nss_t.SECKEYPrivateKey.ptr,
                                                 this.nss_t.PK11SlotInfo.ptr, this.nss_t.PK11SymKey.ptr,
                                                 this.nss_t.CK_MECHANISM_TYPE, this.nss_t.SECItem.ptr,
                                                 this.nss_t.SECItem.ptr, this.nss_t.SECItem.ptr,
                                                 this.nss_t.SECItem.ptr, this.nss_t.PRBool,
                                                 this.nss_t.PRBool, this.nss_t.CK_KEY_TYPE,
                                                 this.nss_t.CK_ATTRIBUTE_TYPE.ptr, ctypes.int,
                                                 ctypes.voidptr_t);
    // security/nss/lib/pk11wrap/pk11pub.h#447
    // PK11SymKey *PK11_PubUnwrapSymKey(SECKEYPrivateKey *key, SECItem *wrapppedKey,
    //         CK_MECHANISM_TYPE target, CK_ATTRIBUTE_TYPE operation, int keySize);
    this.nss.PK11_PubUnwrapSymKey = nsslib.declare("PK11_PubUnwrapSymKey",
                                                   ctypes.default_abi, this.nss_t.PK11SymKey.ptr,
                                                   this.nss_t.SECKEYPrivateKey.ptr, this.nss_t.SECItem.ptr,
                                                   this.nss_t.CK_MECHANISM_TYPE, this.nss_t.CK_ATTRIBUTE_TYPE, ctypes.int);
    // security/nss/lib/pk11wrap/pk11pub.h#675
    // void PK11_DestroyContext(PK11Context *context, PRBool freeit);
    this.nss.PK11_DestroyContext = nsslib.declare("PK11_DestroyContext",
                                                  ctypes.default_abi, ctypes.void_t,
                                                  this.nss_t.PK11Context.ptr, this.nss_t.PRBool);
    // security/nss/lib/pk11wrap/pk11pub.h#299
    // void PK11_FreeSymKey(PK11SymKey *key);
    this.nss.PK11_FreeSymKey = nsslib.declare("PK11_FreeSymKey",
                                              ctypes.default_abi, ctypes.void_t,
                                              this.nss_t.PK11SymKey.ptr);
    // security/nss/lib/pk11wrap/pk11pub.h#70
    // void PK11_FreeSlot(PK11SlotInfo *slot);
    this.nss.PK11_FreeSlot = nsslib.declare("PK11_FreeSlot",
                                            ctypes.default_abi, ctypes.void_t,
                                            this.nss_t.PK11SlotInfo.ptr);
    // security/nss/lib/util/secitem.h#114
    // extern void SECITEM_FreeItem(SECItem *zap, PRBool freeit);
    this.nss.SECITEM_FreeItem = nsslib.declare("SECITEM_FreeItem",
                                               ctypes.default_abi, ctypes.void_t,
                                               this.nss_t.SECItem.ptr, this.nss_t.PRBool);
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
    // security/nss/lib/util/secoid.h#103
    // extern void SECOID_DestroyAlgorithmID(SECAlgorithmID *aid, PRBool freeit);
    this.nss.SECOID_DestroyAlgorithmID = nsslib.declare("SECOID_DestroyAlgorithmID",
                                                        ctypes.default_abi, ctypes.void_t,
                                                        this.nss_t.SECAlgorithmID.ptr, this.nss_t.PRBool);

    this.nss.SECKEY_ConvertToPublicKey = nsslib.declare("SECKEY_ConvertToPublicKey",
                                                       ctypes.default_abi, this.nss_t.SECKEYPublicKey.ptr, this.nss_t.SECKEYPrivateKey.ptr);

    /*
     * Creates a PublicKey from its DER encoding.
     * Currently only supports RSA and DSA keys.
    */
    this.nss.SECKEY_PublicKeyStrengthInBits = 
      nsslib.declare("SECKEY_PublicKeyStrengthInBits", 
                     ctypes.default_abi, ctypes.unsigned_int, 
                     this.nss_t.SECKEYPublicKey.ptr);
    // security/nss/lib/cryptohi/keyhi.h#58
    // extern void SECKEY_DestroySubjectPublicKeyInfo(CERTSubjectPublicKeyInfo *spki);
    this.nss.SECKEY_DestroySubjectPublicKeyInfo = nsslib.declare("SECKEY_DestroySubjectPublicKeyInfo",
                                                                 ctypes.default_abi, ctypes.void_t,
                                                                 this.nss_t.CERTSubjectPublicKeyInfo.ptr);
//SECStatus PK11_ReadRawAttribute(PK11ObjectType type, void *object,
//        CK_ATTRIBUTE_TYPE attr, SECItem *item);
    this.nss.PK11_ReadRawAttribute = nsslib.declare("PK11_ReadRawAttribute",
                                                    ctypes.default_abi, this.nss_t.SECStatus, this.nss_t.SECStatus, ctypes.voidptr_t, this.nss_t.PK11AttrFlags, this.nss_t.SECItem.ptr);
                                                    //        this.nss_t.SECKEYPublicKey.ptr.ptr, this.nss_t.PK11AttrFlags, ctypes.voidptr_t);
//        CK_ATTRIBUTE_TYPE attr, SECItem *item);
  },

  sign : function _sign(encodedPrivateKey, encodedPublicKey, hash) {
    this.log("sign() called");
    let privKey, slot, _hash, sig;

    slot = this.nss.PK11_GetInternalSlot();
    if (slot.isNull())
      throw new Error("couldn't get internal slot");
    wrappedPrivKey = this.makeSECItem(encodedPrivateKey, true);
    var _encodedPublicKey = this.makeSECItem(encodedPublicKey, true);

    let privKey = new this.nss_t.SECKEYPrivateKey.ptr();
    _hash = this.makeSECItem(hash, true);

    sig = this.makeSECItem("", false);

    var rv = this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, wrappedPrivKey.address(),null,_encodedPublicKey.address(),false,true, (0x7fffffff >>> 0), privKey.address());

    if (privKey.isNull()) {
      throw new Error("sign error: Could not unwrap private key: incorrect passphrase entered");
    }

    let sigLen = this.nss.PK11_SignatureLen(privKey);
    sig.len = sigLen;
    sig.data = new ctypes.ArrayType(ctypes.unsigned_char, sigLen)();

    let status = this.nss.PK11_Sign(privKey, sig.address(), _hash.address());
    if (status == -1)
      throw new Error("Could not sign message");
    return this.encodeBase64(sig.data, sig.len);
  },

  verify : function _verify(encodedPublicKey, signature, hash) {
    this.log("verify() called");
    let pubKeyData = this.makeSECItem(encodedPublicKey, true);
    let pubKey;
    let pubKeyInfo = this.nss.SECKEY_DecodeDERSubjectPublicKeyInfo(pubKeyData.address());
    if (pubKeyInfo.isNull())
      throw new Error("SECKEY_DecodeDERSubjectPublicKeyInfo failed");

    pubKey = this.nss.SECKEY_ExtractPublicKey(pubKeyInfo);
    if (pubKey.isNull())
      throw new Error("SECKEY_ExtractPublicKey failed");


    let sig = this.makeSECItem(signature, false);
    let _hash = this.makeSECItem(hash, false);

    let status =
      this.nss.PK11_Verify(pubKey, sig.address(), _hash.address(), null);

    this.log("verify return " + status); 

    if (status == -1) {
      return false;
    }
    return true;
  },

  generateKeypair : function(keyType, keypairBits, out_fields) {

    var PUB_ALGO = {
      RSA: 1, 
      RSA_E: 2,
      RSA_S: 3,
      ELGAMAL_E: 16,
      DSA: 17, 
      ECDH: 18,
      ECDSA: 19,
      ELGAMAL: 20
    }

    this.log("generateKeypair() called. keytype("+ keyType + ") keybits("+ keypairBits + ")");

    let pubKey, privKey, slot;
    try {
      // Attributes for the private key. We're just going to wrap and extract the
      // value, so they're not critical. The _PUBLIC attribute just indicates the
      // object can be accessed without being logged into the token.
      let attrFlags = (this.nss.PK11_ATTR_SESSION | this.nss.PK11_ATTR_PUBLIC | this.nss.PK11_ATTR_INSENSITIVE);

      pubKey  = new this.nss_t.SECKEYPublicKey.ptr();

      let params, genType;
      switch(keyType)
      {
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
        var rc = this.nss.PK11_PQG_ParamGen(8, pqgparams.address(), pqgverify.address());
        params = pqgparams;

        genType = this.nss.CKM_DSA_KEY_PAIR_GEN;
        break;
        case PUB_ALGO.ELGAMAL_E:
        let dhParams = new this.nss_t.SECKEYDHParams();
        var pqgparams = new this.nss_t.PQGParams.ptr();
        var pqgverify = new this.nss_t.PQGVerify.ptr();
        var rc = this.nss.PK11_PQG_ParamGen(8, pqgparams.address(), pqgverify.address());
        var prime = this.makeSECItem("", false);
        rc = this.nss.PK11_PQG_GetPrimeFromParams(pqgparams, prime.address());
        dhParams.base = this.makeSECItem(String.fromCharCode(5), false);
        dhParams.prime = prime;//this.makeSECItem(pqgparams.prime.ptr, false);
        params = dhParams.address();
        genType = this.nss.CKM_DH_PKCS_KEY_PAIR_GEN;
        break;
        default:
        throw new Error("Invalid public key algo");
      }

      slot = this.nss.PK11_GetInternalSlot();
      if (slot.isNull())
        throw new Error("couldn't get internal slot");

      // Generate the keypair.
      privKey = this.nss.PK11_GenerateKeyPairWithFlags(slot,
                                                       genType,
                                                       params,
                                                       pubKey.address(),
                                                       attrFlags, null);
      //let derKey = this.nss.SECKEY_EncodeDERSubjectPublicKeyInfo(pubKey);
      //if (derKey.isNull())
      //  throw new Error("SECKEY_EncodeDERSubjectPublicKeyInfo failed");
      if (keyType == PUB_ALGO.DSA) {
      let derKey = this.nss.SECKEY_EncodeDERSubjectPublicKeyInfo(pubKey);
      if (derKey.isNull())
        throw new Error("SECKEY_EncodeDERSubjectPublicKeyInfo failed");
      let encodedPublicKey =this.encodeBase64(derKey.contents.data, derKey.contents.len);
      }
      out_fields.pubkey = encodedPublicKey;


      let encodedPublicKey = btoa("asdf");//this.encodeBase64("asdf", 4);//derKey.contents.data, derKey.contents.len);

      if (privKey.isNull())
        throw new Error("keypair generation failed");

      let s = this.nss.PK11_SetPrivateKeyNickname(privKey, "Weave User PrivKey");
      if (s)
        throw new Error("key nickname failed");

      let wrappedKey;
      try {

        // Use a buffer to hold the wrapped key. NSS says about 1200 bytes for
        // a 2048-bit RSA key, so a 4096 byte buffer should be plenty.
        let keyData = new ctypes.ArrayType(ctypes.unsigned_char, 4096)();
        wrappedKey = new this.nss_t.SECItem(this.nss.SIBUFFER, keyData, keyData.length);

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
        var CKA_PUBLIC_EXPONENT  = 0x00000122;
        var CKA_VALUE            = 0x00000011;
        var CKA_DERIVE           = 0x0000010C;

        function getAttribute(self, privKey, attrtype)
        {
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
          var CKA_NETSCAPE_DB = 0xD5A0DB00;
          out_fields.y = getAttribute(this, privKey, CKA_NETSCAPE_DB);
          break;
          case PUB_ALGO.DSA:
          out_fields.p = getAttribute(this, privKey, CKA_PRIME);
          out_fields.q = getAttribute(this, privKey, CKA_SUBPRIME);
          out_fields.g = getAttribute(this, privKey, CKA_BASE);
          out_fields.x = getAttribute(this, privKey, CKA_VALUE);

          var CKA_NETSCAPE_DB = 0xD5A0DB00;
          out_fields.y = getAttribute(this, privKey, CKA_NETSCAPE_DB);
          break;
          default:
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

  wrapSymmetricKey : function(_symmetricKey, encodedPublicKey) {
    this.log("wrapSymmetricKey() called");

    // Step 1. Get rid of the base64 encoding on the inputs.

    let pubKeyData = this.makeSECItem(encodedPublicKey, true);
    let symKeyData = this.makeSECItem(_symmetricKey, true);
    let symmetricKey = atob(_symmetricKey);
    // This buffer is much larger than needed, but that's ok.
    let keyData = new ctypes.ArrayType(ctypes.unsigned_char, 4096)();
    let wrappedKey = new this.nss_t.SECItem(this.nss.SIBUFFER, keyData, keyData.length);

    // Step 2. Put the symmetric key bits into a P11 key object.
    let slot, symKey, pubKeyInfo, pubKey;
    try {
      slot = this.nss.PK11_GetInternalSlot();
      if (slot.isNull())
        throw new Error("couldn't get internal slot");

      pubKeyInfo = this.nss.SECKEY_DecodeDERSubjectPublicKeyInfo(pubKeyData.address());
      if (pubKeyInfo.isNull())
        throw new Error("SECKEY_DecodeDERSubjectPublicKeyInfo failed");

      pubKey = this.nss.SECKEY_ExtractPublicKey(pubKeyInfo);
      if (pubKey.isNull())
        throw new Error("SECKEY_ExtractPublicKey failed");
      

      // Step 4. Wrap the symmetric key with the public key.
      var byteLen = this.nss.SECKEY_PublicKeyStrengthInBits(pubKey) / 8; 

      let output = "";
      for (var i=0;i<byteLen;i++)
        output += String.fromCharCode(0);

      let inputData = new ctypes.ArrayType(ctypes.unsigned_char, symmetricKey.length)(); 
      this.byteCompress(symmetricKey, inputData);
      let outputData = new ctypes.ArrayType(ctypes.unsigned_char, output.length)(); 
      this.byteCompress(output, outputData);

      let s = this.nss.PK11_PubEncryptPKCS1(pubKey, outputData, inputData, symmetricKey.length, null); 
      //let s = this.nss.PK11_PubEncryptRaw(pubKey, outputData, inputData, symmetricKey.length, null); 

      if (s)
        throw new Error("PK11_PubWrapSymKey failed");


      //XXX missing verify checksum
      var out = "";
      for (var i=0; i<outputData.length;i++)
        out += String.fromCharCode(outputData[i]);

      return btoa(out);

    } catch (e) {
      this.log("wrapSymmetricKey: failed: " + e);
      throw e;
    } finally {
      if (pubKey && !pubKey.isNull())
        this.nss.SECKEY_DestroyPublicKey(pubKey);
      if (pubKeyInfo && !pubKeyInfo.isNull())
        this.nss.SECKEY_DestroySubjectPublicKeyInfo(pubKeyInfo);
      if (symKey && !symKey.isNull())
        this.nss.PK11_FreeSymKey(symKey);
      if (slot && !slot.isNull())
        this.nss.PK11_FreeSlot(slot);
    }
  },


  //XXX unwrap secret key/import DER encoded if not protected
  unwrapSymmetricKey : function(wrappedSymmetricKey, wrappedPrivateKey) {
    this.log("unwrapSymmetricKey() called");
    // Step 1. Get rid of the base64 encoding on the inputs.
    let wrappedPrivKey = this.makeSECItem(wrappedPrivateKey, true);
    let wrappedSymKey  = this.makeSECItem(wrappedSymmetricKey, true);
    var byteLen = atob(wrappedSymmetricKey).length;

    let slot, privKey;
    try {

      slot = this.nss.PK11_GetInternalSlot();
      if (slot.isNull())
        throw new Error("couldn't get internal slot");
      let privKey = new this.nss_t.SECKEYPrivateKey.ptr();

      var rv = this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, wrappedPrivKey.address(),null,null,false,true, (0x7fffffff >>> 0), privKey.address());
      if (privKey.isNull())
        throw new Error("Import DER private key failed");
      var outlen = new ctypes.unsigned;
      let input = atob(wrappedSymmetricKey);

      let output = [];
      for (var i=0;i<input.length;i++)
        output[i] = 0;

      output = misc.atob(output);

      let inputData = new ctypes.ArrayType(ctypes.unsigned_char, input.length)(); this.byteCompress(input, inputData);

      for (var i=0; i<input.length; i++)
        inputData[i] = input.charCodeAt(i);

      let outputData = new ctypes.ArrayType(ctypes.unsigned_char, output.length)(); this.byteCompress(output, outputData);

      rv = this.nss.PK11_PrivDecryptPKCS1(privKey, outputData, 
                                          outlen.address(), byteLen, inputData, byteLen);

      return this.encodeBase64( outputData.address(), outputData.length );

    } catch (e) {
      this.log("unwrapSymmetricKey: failed: " + e);
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


    let outputData = new ctypes.ArrayType(ctypes.unsigned_char, input.length)(); this.byteCompress(input, outputData);

    return new this.nss_t.SECItem(this.nss.SIBUFFER, outputData, outputData.length);
  },
};


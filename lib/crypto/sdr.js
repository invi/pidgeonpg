var {Cu, Ci, Cc} = require("chrome");
var {XPCOMUtils} = Cu.import("resource://gre/modules/XPCOMUtils.jsm");
const misc = require('util/misc');
const {hashData} = require('crypto/hash.js');
const {keyExpansion} = require("crypto/symmetricencryption/aes");

XPCOMUtils.defineLazyServiceGetter(this, "sdr",
                                   "@mozilla.org/security/sdr;1",
                                   "nsISecretDecoderRing");

XPCOMUtils.defineLazyServiceGetter(this, "promptSvc",
                                   "@mozilla.org/embedcomp/prompt-service;1",
                                   "nsIPromptService");

var PASSPHRASE_TTL = 3600000;

/**
 * produces a key using the specified passphrase and the defined hashAlgorithm 
 * @param passphrase [String] passphrase containing user input
 * @return [String] produced key with a length corresponding to hashAlgorithm hash length
 */
function produce_key(hashAlgorithm, mode, saltValue, c, passphrase) {
  var ret = "";
	switch (mode) {
    case 0:
		ret = hashData(hashAlgorithm, passphrase);
    break;

    case 1:
		ret = hashData(hashAlgorithm, saltValue+passphrase);
    break;

    case 3:
    var EXPBIAS = 6;
	  var count = (16 + (c & 15)) << ((c >> 4) + EXPBIAS);
		var isp = saltValue + passphrase;
		while (isp.length < count)
			isp += saltValue + passphrase; 			
	  isp = isp.substr(0, count);
		ret = hashData(hashAlgorithm, isp);
    break;

    default:
    ret = null;
	} 
  return ret;
}


var Ski = {
/**
 * Decrypts the private key MPIs which are needed to use the key.
 * openpgp_packet_keymaterial.hasUnencryptedSecretKeyData should be false otherwise
 * a call to this function is not needed
 * 
 * @param str_passphrase the passphrase for this private key as string
 * @return true if the passphrase was correct; false if not
 */
  generate: function(skey) {
    const NOB = 8; // number of bytes  
    var IV =  misc.atos(prng.getService(Ci.nsIRandomGenerator).generateRandomBytes(NOB, "asdfqwersadf"));  
    var saltValue = misc.atos(prng.getService(Ci.nsIRandomGenerator).generateRandomBytes(NOB, "asdfsfsdfsd"));  
  
    var ski = { 
                usage: 254,
                s2k: {
                  mode: 3,
                  hash_algo: 2,
                  salt: misc.stoa(saltValue),
                  count: 96,
                },
                sym_algo: 3,
                iv: misc.stoa(IV),
              };
  
    var {passphrase} = this.promptNewPassphrase();
  	var symkey = produce_key(ski.s2k.hash_algo, ski.s2k.mode, ski.s2k, ski.s2k.count, passphrase);
  
  	var cleartextMPIs = "";
    for (var i=0;i<skey.length;i++) 
      cleartextMPIs += skey[i];
  
    if (ski.usage == 254)
      cleartextMPIs += hashData(2, cleartextMPIs);  
    else 
      cleartextMPIs += misc.calc_checksum(cleartextMPIs)
  
    var wrapped_skey = normal_cfb_encrypt(function(block, key) {
    		var cast5 = new openpgp_symenc_cast5();
    		cast5.setKey(key);
    		return cast5.encrypt(misc.str2bin(block)); 
    }, IV.Length, misc.str2bin(symkey.substring(0,16)), cleartextMPIs, IV);
  
    return {skey: [encryptedMPIData], ski: ski};
  },
  promptNewPassphrase: function() {
    let passphrase1 = {};
    let passphrase2 = {};
    do {
      var prompt1 = promptSvc.promptPassword(null,
                               "enterPassphraseTitle",
                               "enterPassphraseText",
                               passphrase1, null, { value: false });
      var prompt2 = promptSvc.promptPassword(null,
                               "confirmPassphraseTitle",
                               "confirmPassphraseText",
                               passphrase2, null, { value: false });
    
    } while(passphrase1.value == passphrase2.value);

    return {passphrase: passphrase1.value};
  },
  promptPassphrase: function() {
    let passphrase = {};
    let prompt;
      promptSvc.promptPassword(null,
                               "enterPassphraseTitle",
                               "enterPassphraseText",
                               passphrase, null, { value: false });
    
    return {passphrase: passphrase.value, prompt: prompt};
  },

  /**
   * Decrypts the private key MPIs which are needed to use the key.
   * openpgp_packet_keymaterial.hasUnencryptedSecretKeyData should be false otherwise
   * a call to this function is not needed
   * 
   * @param str_passphrase the passphrase for this private key as string
   * @return true if the passphrase was correct; false if not
   */
  unwrapSkey: function(ski, wrapped_skey) {
    var encryptedMPIData = skey[0];
    var saltValue = misc.atos(ski.s2k.salt);
    var {sym_algo, usage} = ski;
    var IV = misc.atos(ski.iv);
  	var symkey = produce_key(ski.s2k.hash_algo, ski.s2k.mode, saltValue, 
                             ski.s2k.count, this.enterPassphrase());
  	var cleartextMPIs = "";
  
    switch (ski.sym_algo) {
    case  1: // - IDEA [IDEA]
    	throw Error("symmetric encryption algorithim: IDEA is not implemented");
    case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
    	cleartextMPIs = normal_cfb_decrypt(function(block, key) {
    		return des(key, block,1,null,0);
    	}, IV.length, symkey, encryptedMPIData, IV);
    	break;
    case  3: // - CAST5 (128 bit key, as per [RFC2144])
    	cleartextMPIs = normal_cfb_decrypt(function(block, key) {
      		var cast5 = new openpgp_symenc_cast5();
      		cast5.setKey(key);
      		return cast5.encrypt(util.str2bin(block)); 
    	}, IV.length, misc.str2bin(symkey.substring(0,16)), encryptedMPIData, IV);
    	break;
    case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
    	cleartextMPIs = normal_cfb_decrypt(function(block, key) {
    		var blowfish = new Blowfish(key);
      		return blowfish.encrypt(block); 
    	}, IV.length, symkey, encryptedMPIData, IV);
    	break;
    case  7: // - AES with 128-bit key [AES]
    case  8: // - AES with 192-bit key
    case  9: // - AES with 256-bit key	    	
    	cleartextMPIs = normal_cfb_decrypt(AESencrypt,
    			IV.length, keyExpansion(symkey), encryptedMPIData, IV);
    	break;
    case 10: // - Twofish with 256-bit key [TWOFISH]
    	throw Error("Key material is encrypted with twofish: not implemented");   		
    case  5: // - Reserved
    case  6: // - Reserved
    default:
    	throw Error("Unknown encryption algorithm for secret key: "+sym_algo);
    }
    
    if (cleartextMPIs == null) {
    	throw Error("cleartextMPIs was null");
    }
    
    //XXX remember me
    var cleartextMPIslength = cleartextMPIs.length;
    if (usage == 254 &&
    	  hashData(2, cleartextMPIs.substring(0,cleartextMPIs.length - 20)) == 
    			cleartextMPIs.substring(cleartextMPIs.length - 20)) {
    } else if (usage != 254 && misc.calc_checksum(cleartextMPIs.substring(0,cleartextMPIs.length - 2)) == 
    		(cleartextMPIs.charCodeAt(cleartextMPIs.length -2) << 8 | cleartextMPIs.charCodeAt(cleartextMPIs.length -1))) {
    } else {
    	return false;
    }
  
    return misc.mpi_read_seckey(secObj.pubkey_algo, cleartextMPIs);
  }
}

/*
function secretDecoderRing() {
  this.seckeys = { };
}

function setSecretMPIs(pkey, skey, passphrase) {
  if (typeof passphrase == "string" && passphrase.length) { 
    var secObj = g4bcrypto.encryptSecretMPIs(skey, passphrase);
    sdr.setPassphrase(pkey, passphrase);
    return secObj;
  }
  else
    return { usage: 0, skey : skey };
}

function getSecretMPIs(pkey, _secObj) {
  if (_secObj.usage) {
    var passphrase = sdr.enterPassphrase(pkey);
    var secObj = g4bcrypto.decryptSecretMPIs(_secObj, passphrase);
    if (!secObj) {
      throw new Error("PGP.ERR.INV_PASSPHRASE");
    }
    sdr.setPassphrase(pkey, passphrase);
    return secObj;
  }
  else
    return _secObj.skey;
}

secretDecoderRing.prototype.enterPassphrase = function(pkey) {
  var pubkey = pkey[0];
  var passphrase = "";

  if (pubkey in this.seckeys) {
    if ((Date.now() - this.seckeys[pubkey].lastEntered) > PASSPHRASE_TTL)  {
      passphrase = promptPassphrase().passphrase;
      if (passphrase == sdr.decryptString(this.seckeys[pubkey].passphrase))
        this.seckeys[pubkey].lastEntered = Date.now();
    } else 
      passphrase = sdr.decryptString(this.seckeys[pubkey].passphrase);
  } else
    passphrase = promptPassphrase().passphrase;

  return passphrase;
}

secretDecoderRing.prototype.setPassphrase = function(pkey, passphrase) {
  var pubkey = pkey[0];
  this.seckeys[pubkey] = { };
  this.seckeys[pubkey].lastEntered = Date.now();
  this.seckeys[pubkey].passphrase = sdr.encryptString(passphrase);
}

function init() {
  return new secretDecoderRing();
}

exports.init = init;

*/

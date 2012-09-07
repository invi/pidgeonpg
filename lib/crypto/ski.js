var {Cu, Ci, Cc} = require("chrome");
var prng = Cc['@mozilla.org/security/random-generator;1'];  

const {openpgp_symenc_cast5, cast5_encrypt} = require("crypto/symmetric/cast5");
const logger = require('util/logger').create('ski.js');
const misc = require('util/misc');
const {hashData} = require('crypto/hash.js');
const {keyExpansion} = require("crypto/symmetric/aes");
const {normal_cfb_decrypt, normal_cfb_encrypt} = require("crypto/symmetric/openpgp.cfb.js"); 
const {prompt} = require("util/prompt.js"); 
const base64Decode = require("api-utils/base64").decode;
const base64Encode = require("api-utils/base64").encode;
const PASSPHRASE_TTL = 3600000;

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

  cached: [],

  wrapSkey: function(ski, skey, passphrase) {
    var IV = misc.atos(ski.iv);
    var saltValue = misc.atos(ski.s2k.salt);

    if (ski.usage != 0) {
  	  var symkey = produce_key(ski.s2k.hash_algo, ski.s2k.mode, ski.s2k.salt, ski.s2k.count, passphrase);
  	  var cleartextMPIs = "";
      for (var i=0;i<skey.length;i++) 
        cleartextMPIs += skey[i];

      if (ski.usage == 254)
        cleartextMPIs += hashData(2, cleartextMPIs);  
      else 
        cleartextMPIs += misc.calc_checksum(cleartextMPIs)

      var wrapped_skey = normal_cfb_encrypt(function(block, key) {
        var ret = "";
        try {
      		var cast5 = new openpgp_symenc_cast5();
      		cast5.setKey(key);
      		ret = cast5.encrypt(misc.str2bin(block)); 
        } catch(err) { 
          logger.error(err) 
        } finally {
          return ret;
        }
      }, IV.length, misc.str2bin(symkey.substring(0,16)), cleartextMPIs, IV);
      return [ wrapped_skey ];
    }
    return skey;
  },

  generate: function(skey, primarySki) {

    const NOB = 8; // number of bytes  
    var ski;
    var passphrase = "";

    if (primarySki) {
      ski = primarySki;
      if (ski.usage != 0) {
        passphrase = this.getCachedPassphrase(ski);
      }
    } else { 
      passphrase = this.enterNewPassphrase();
      if (passphrase == "") {
        ski = { 
          usage: 0,
          s2k: {
            mode: 0,
          },
        };
      } else {
        IV =  prng.getService(Ci.nsIRandomGenerator).generateRandomBytes(NOB, "asdfqwersadf");  
        saltValue = prng.getService(Ci.nsIRandomGenerator).generateRandomBytes(NOB, "asdfsfsdfsd");  
        ski = { 
          usage: 254,
          s2k: {
            mode: 3,
            hash_algo: 2,
            salt: saltValue,
            count: 96,
          },
          algo: 3,
          iv: IV,
        };
      }
    }

    var ret_skey;
    if (ski.usage)
      ret_skey = this.wrapSkey(ski, skey, passphrase);
    else 
      ret_skey = skey;

  
    return {skey: ret_skey, ski: ski};
  },

  removeWrongPassphrase: function(ski) {
    var ski64 = base64Encode(JSON.stringify(ski));
    for (var i=0; i<this.cached.length; i++) {
      if (ski64 == this.cached[i].ski) 
        delete this.cached[i];
    } 
  },

  enterNewPassphrase: function(ski) {
    var {passphrase} = prompt.newPassphrase();
    var ski64 = base64Encode(JSON.stringify(ski));
    if (passphrase) 
      this.cached.push({passphrase: passphrase,
                        last_entered: Date.now(),
                        ski: ski64});
    return passphrase;
  },

  getCachedPassphrase: function(_ski) {
    var ski64 = base64Encode(JSON.stringify(_ski));
    for (var i=0; i<this.cached.length; i++) {
      var {last_entered, ski, passphrase} = this.cached[i];
      if (ski == ski64) {
        if ((Date.now() - last_entered) > PASSPHRASE_TTL) {
          var enteredPassphrase = prompt.enterPassphrase();
          this.cached[i].passphrase = enteredPassphrase;
          this.cached[i].last_entered = Date.now;
          return enteredPassphrase;
        }
        else 
          return passphrase;
      }
    } 
    var enteredPassphrase = prompt.enterPassphrase();
    this.cached.push({passphrase: enteredPassphrase,
                      last_entered: Date.now(),
                      ski: ski64});
    return enteredPassphrase;
  },

  /**
   * Decrypts the private key MPIs which are needed to use the key.
   * openpgp_packet_keymaterial.hasUnencryptedSecretKeyData should be false otherwise
   * a call to this function is not needed
   * 
   * @param str_passphrase the passphrase for this private key as string
   * @return true if the passphrase was correct; false if not
   */
  unwrapSkey: function(pubkey_algo, ski, wrapped_skey) {
    var {usage} = ski;
    if (usage == 0) return wrapped_skey;

    var encryptedMPIData = wrapped_skey[0];
    var {algo} = ski;
    var IV = misc.atos(ski.iv);
    var passphrase = this.getCachedPassphrase(ski);
  	var symkey = produce_key(ski.s2k.hash_algo, ski.s2k.mode, ski.s2k.salt, 
                             ski.s2k.count, passphrase);
  	var cleartextMPIs = "";
  
    switch (algo) {
    case  1: // - IDEA [IDEA]
    	throw Error("symmetric encryption algorithim: IDEA is not implemented");
    case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
    	cleartextMPIs = normal_cfb_decrypt(function(block, key) {
    		return des(key, block,1,null,0);
    	}, IV.length, symkey, encryptedMPIData, IV);
    	break;
    case  3: // - CAST5 (128 bit key, as per [RFC2144])
    	cleartextMPIs = normal_cfb_decrypt(function(block, key) {
          var ret;
          try {
      		  var cast5 = new openpgp_symenc_cast5();
      		  cast5.setKey(key);
      		  ret = cast5.encrypt(misc.str2bin(block)); 
          } catch(err) {
            logger.error(err) 
          } finally {
            return ret;
          }
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
    	throw Error("Unknown encryption algorithm for secret key: "+algo);
    }
    
    if (cleartextMPIs == null) {
    	throw Error("cleartextMPIs was null");
    }
    
    if (usage == 254 &&
    	  hashData(2, cleartextMPIs.substring(0,cleartextMPIs.length - 20)) == 
    			cleartextMPIs.substring(cleartextMPIs.length - 20)) {
    } else if (usage != 254 && misc.calc_checksum(cleartextMPIs.substring(0,cleartextMPIs.length - 2)) == 
    		(cleartextMPIs.charCodeAt(cleartextMPIs.length -2) << 8 | cleartextMPIs.charCodeAt(cleartextMPIs.length -1))) {
    } else {
      this.removeWrongPassphrase(ski); 
    	return false;
    }
    return misc.mpi_read_seckey(pubkey_algo, cleartextMPIs);
  }
}

exports.Ski = Ski;

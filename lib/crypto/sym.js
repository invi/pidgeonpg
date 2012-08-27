var {Cu, Ci, Cc} = require("chrome");
//var prng = Cc['@mozilla.org/security/random-generator;1'];  
const {keyExpansion, AESencrypt} = require("crypto/symmetric/aes");
//const {openpgp_symenc_cast5, cast5_encrypt} = require("crypto/symmetric/cast5");
const {openpgp_cfb_decrypt,
       openpgp_cfb_encrypt} = require("crypto/symmetric/openpgp.cfb");
const logger = require("util/logger").create('sym.js');
const misc = require('util/misc');
const {domcrypt} = require('crypto/asymmetric/domcrypt');
const base64Decode = require("api-utils/base64").decode;
/*
 * retrieve secure random byte string of the specified length
 * @param length [Integer] length in bytes to generate
 * @return [String] random byte string
 */
function openpgp_crypto_getRandomBytes(length, callback) {
  domcrypt.generateRandom(length, function(data) { 
    callback(base64Decode(data)); 
  });
  return 0;
}

/**
 * generate random byte prefix as string for the specified algorithm
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @return [String] random bytes with length equal to the block
 * size of the cipher
 */
function openpgp_crypto_getPrefixRandom(algo, callback) {
	switch(algo) {
	case 2:
	case 3:
	case 4:
		return openpgp_crypto_getRandomBytes(8, callback);
	case 7:
	case 8:
	case 9:
	case 10:
		return openpgp_crypto_getRandomBytes(16, callback);
	default:
		return null;
	}
}

/**
 * Generating a session key for the specified symmetric algorithm
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @return [String] random bytes as a string to be used as a key
 */
function openpgp_crypto_generateSessionKey(algo, callback) {
	switch (algo) {
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	case 8: // AES with 192-bit key
		return openpgp_crypto_getRandomBytes(24, callback); 
	case 3: // CAST5 (128 bit key, as per [RFC2144])
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	case 7: // AES with 128-bit key [AES]
		return openpgp_crypto_getRandomBytes(16, callback);
	case 9: // AES with 256-bit key
	case 10:// Twofish with 256-bit key [TWOFISH]
		return openpgp_crypto_getRandomBytes(32, callback);
	}
  throw Error("Symmetric algorithm (" + algo + ") not supported"); 
}

/**
 * retrieve the MDC prefixed bytes by decrypting them
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @param key [String] key as string. length is depending on the algorithm used
 * @param data [String] encrypted data where the prefix is decrypted from
 * @return [String] plain text data of the prefixed data
 */
function openpgp_crypto_MDCSystemBytes(algo, key, data) {
	util.print_debug("openpgp_crypto_symmetricDecrypt:\nencrypteddata:"+util.hexstrdump(data));
	switch(algo) {
	case 0: // Plaintext or unencrypted data
		return data;
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
		return openpgp_cfb_mdc(desede, 8, key, data, openpgp_cfb);
	case 3: // CAST5 (128 bit key, as per [RFC2144])
		return openpgp_cfb_mdc(cast5_encrypt, 8, key, data);
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		return openpgp_cfb_mdc(BFencrypt, 8, key, data);
	case 7: // AES with 128-bit key [AES]
	case 8: // AES with 192-bit key
	case 9: // AES with 256-bit key
		return openpgp_cfb_mdc(AESencrypt, 16, keyExpansion(key), data);
	case 10: 
		return openpgp_cfb_mdc(TFencrypt, 16, key, data);
	case 1: // IDEA [IDEA]
		util.print_error(""+ (algo == 1 ? "IDEA Algorithm not implemented" : "Twofish Algorithm not implemented"));
		return null;
	default:
	}
	return null;
}

/**
 * Symmetrically decrypts data using a key with length depending on the
 * algorithm in openpgp_cfb mode with or without resync (MDC style)
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @param key [String] key as string. length is depending on the algorithm used
 * @param data [String] data to be decrypted
 * @param openpgp_cfb [boolean] if true use the resync (for encrypteddata); 
 * otherwise use without the resync (for MDC encrypted data)
 * @return [String] plaintext data
 */
function openpgp_crypto_symmetricDecrypt(algo, key, data, openpgp_cfb) {
	logger.debug("openpgp_crypto_symmetricDecrypt:\nalgo:"+algo+"\nencrypteddata:"+misc.hexstrdump(data));
	var n = 0;
	if (!openpgp_cfb)
		n = 2;
	switch(algo) {
	case 0: // Plaintext or unencrypted data
		return data;
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
		return openpgp_cfb_decrypt(desede, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 3: // CAST5 (128 bit key, as per [RFC2144])
		return openpgp_cfb_decrypt(cast5_encrypt, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		return openpgp_cfb_decrypt(BFencrypt, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 7: // AES with 128-bit key [AES]
	case 8: // AES with 192-bit key
	case 9: // AES with 256-bit key
		return openpgp_cfb_decrypt(AESencrypt, 16, keyExpansion(key), data, openpgp_cfb).substring(n, (data.length+n)-18);
	case 10: // Twofish with 256-bit key [TWOFISH]
		var result = openpgp_cfb_decrypt(TFencrypt, 16, key, data, openpgp_cfb).substring(n, (data.length+n)-18);
		return result;
	case 1: // IDEA [IDEA]
		util.print_error(""+ (algo == 1 ? "IDEA Algorithm not implemented" : "Twofish Algorithm not implemented"));
		return null;
	default:
	}
	return null;
}

/**
 * Symmetrically encrypts data using prefixedrandom, a key with length 
 * depending on the algorithm in openpgp_cfb mode with or without resync
 * (MDC style)
 * @param prefixrandom secure random bytes as string in length equal to the
 * block size of the algorithm used (use openpgp_crypto_getPrefixRandom(algo)
 * to retrieve that string
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @param key [String] key as string. length is depending on the algorithm used
 * @param data [String] data to encrypt
 * @param openpgp_cfb [boolean]
 * @return [String] encrypted data
 */
function openpgp_crypto_symmetricEncrypt(prefixrandom, algo, key, data, openpgp_cfb) {
	switch(algo) {
		case 0: // Plaintext or unencrypted data
			return data; // blockcipherencryptfn, plaintext, block_size, key
		case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
			return openpgp_cfb_encrypt(prefixrandom, desede, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 3: // CAST5 (128 bit key, as per [RFC2144])
			return openpgp_cfb_encrypt(prefixrandom, cast5_encrypt, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
			return openpgp_cfb_encrypt(prefixrandom, BFencrypt, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 7: // AES with 128-bit key [AES]
		case 8: // AES with 192-bit key
		case 9: // AES with 256-bit key
			return openpgp_cfb_encrypt(prefixrandom, AESencrypt, data, 16, keyExpansion(key), openpgp_cfb).substring(0, data.length + 18);
		case 10: // Twofish with 256-bit key [TWOFISH]
			return openpgp_cfb_encrypt(prefixrandom, TFencrypt, data,16, key, openpgp_cfb).substring(0, data.length + 18);
		case 1: // IDEA [IDEA]
			util.print_error("IDEA Algorithm not implemented");
			return null;
		default:
			return null;
	}
}

exports.getPrefixRandom = openpgp_crypto_getPrefixRandom;
exports.generateSessionKey = openpgp_crypto_generateSessionKey;
exports.generateRandom = openpgp_crypto_getRandomBytes;

exports.encrypt = openpgp_crypto_symmetricEncrypt;
exports.decrypt = openpgp_crypto_symmetricDecrypt;



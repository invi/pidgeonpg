const {Cc, Ci, Cr, Cu, components} = require("chrome");
const logger = require('util/logger').create('g4bcrypto.js');
const {hashData} = require('crypto/hash');
const pkcs1 = require("encode/pkcs1");
const {data} = require('self');
const misc = require('util/misc');

var {ChromeWorker} = Cu.import("resource://gre/modules/Services.jsm", null);

var worker = new ChromeWorker(data.url("workers/gpg4browsers_worker.js"));

var Callbacks = {};
worker.onmessage = function(aEvent) {
  var res = JSON.parse(aEvent.data);
  Callbacks[res.ts](res.value);
  delete Callbacks[res.ts];
}

// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA 

// The GPG4Browsers crypto interface

/**
 * Encrypts data using the specified public key multiprecision integers 
 * and the specified algorithm.
 * @param algo [Integer] Algorithm to be used (See RFC4880 9.1)
 * @param publicMPIs [Array[openpgp_type_mpi]] algorithm dependent multiprecision integers
 * @param data [openpgp_type_mpi] data to be encrypted as MPI
 * @return [Object] if RSA an openpgp_type_mpi; if elgamal encryption an array of two
 * openpgp_type_mpi is returned; otherwise null
 */
function openpgp_crypto_asymetricEncrypt(algo, publicMPIs, data, callback) {
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		//var rsa = new RSA();
		//var n = publicMPIs[0].toBigInteger();
		//var e = publicMPIs[1].toBigInteger();
		//var m = data.toBigInteger();
		//return rsa.encrypt(m,e,n).toMPI();
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
    var req = { 
		  p: publicMPIs[0].toString(),
		  g: publicMPIs[1].toString(),
		  y: publicMPIs[2].toString(),
		  m: data,
      ACTION: "Elgamal",
      ts: Date.now(),
    }
    Callbacks[req.ts] = callback;
    worker.postMessage(JSON.stringify(req));
    break;
  default:
  	return null;
  }
}

/**
 * Decrypts data using the specified public key multiprecision integers of the private key,
 * the specified secretMPIs of the private key and the specified algorithm.
 * @param algo [Integer] Algorithm to be used (See RFC4880 9.1)
 * @param publicMPIs [Array[openpgp_type_mpi]] algorithm dependent multiprecision integers of the public key part of the private key
 * @param secretMPIs [Array[openpgp_type_mpi]] algorithm dependent multiprecision integers of the private key used
 * @param data [openpgp_type_mpi] data to be encrypted as MPI
 * @return [BigInteger] returns a big integer containing the decrypted data; otherwise null
 */
function openpgp_crypto_asymetricDecrypt(algo, publicMPIs, secretMPIs, dataMPIs, callback) {
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var d = secretMPIs[0].toBigInteger();
		var p = secretMPIs[1].toBigInteger();
		var q = secretMPIs[2].toBigInteger();
		var u = secretMPIs[3].toBigInteger();
		var m = dataMPIs[0].toBigInteger();
		return rsa.decrypt(m, d, p, q, u);
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
    var req = {
      ACTION: "ElgamalDecrypt",
		  x: secretMPIs[0].toString(),
		  c1: dataMPIs[0].toString(),
		  c2: dataMPIs[1].toString(),
		  p: publicMPIs[0].toString(),
      ts: Date.now(),
    }
    Callbacks[req.ts] = callback;
    worker.postMessage(JSON.stringify(req));
	default:
		return null;
	}
}

/**
 * 
 * @param algo [Integer] public key algorithm
 * @param hash_algo [Integer] hash algorithm
 * @param msg_MPIs [Array[openpgp_type_mpi]] signature multiprecision integers
 * @param publickey_MPIs [Array[openpgp_type_mpi]] public key multiprecision integers 
 * @param data [String] data on where the signature was computed on.
 * @return true if signature (sig_data was equal to data over hash)
 */
function openpgp_crypto_verifySignature(algo, hash_algo, msg_MPIs, publickey_MPIs, data, callback) {
	//var calc_hash = openpgp_crypto_hashData(hash_algo, data);
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var n = publickey_MPIs[0].toBigInteger();
		var e = publickey_MPIs[1].toBigInteger();
		var x = msg_MPIs[0].toBigInteger();
		var dopublic = rsa.verify(x,e,n);
		var hash  = pkcs1.emsa_decode(hash_algo,dopublic.toMPI().substring(2));
		if (hash == -1) {
			logger.error("PKCS1 padding in message or key incorrect. Aborting...");
			return false;
		}
		return hash == calc_hash;
		
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		logger.error("signing with Elgamal is not defined in the OpenPGP standard.");
		return null;
	case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
    var hash_data = hashData(hash_algo, data); 
    var req = {
      ACTION: "DSAVerify",
		  s1: msg_MPIs[0],
		  s2: msg_MPIs[1],
		  p: publickey_MPIs[0],
		  q: publickey_MPIs[1],
		  g: publickey_MPIs[2],
		  y: publickey_MPIs[3],
		  m: misc.stohex(data),
      ts: Date.now(),
      hash_algo: hash_algo,
      hash_data: hash_data,
    }
    Callbacks[req.ts] = callback;
    worker.postMessage(JSON.stringify(req));
	default:
		return null;
	}
	
}
   
/**
 * Create a signature on data using the specified algorithm
 * @param hash_algo [Integer] hash algorithm to use (See RFC4880 9.4)
 * @param algo [Integer] asymmetric cipher algorithm to use (See RFC4880 9.1)
 * @param publicMPIs [Array[openpgp_type_mpi]] public key multiprecision integers of the private key 
 * @param secretMPIs [Array[openpgp_type_mpi]] private key multiprecision integers which is used to sign the data
 * @param data [String] data to be signed
 * @return [String or openpgp_type_mpi] 
 */
function openpgp_crypto_signData(hash_algo, algo, publicMPIs, secretMPIs, data, callback) {
	
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var d = secretMPIs[0].toBigInteger();
		var n = publicMPIs[0].toBigInteger();
		var m = openpgp_encoding_emsa_pkcs1_encode(hash_algo, data,publicMPIs[0].mpiByteLength);
		logger.debug("signing using RSA");
		return rsa.sign(m, d, n).toMPI();
	case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
		//logger.debug("DSA Sign: q size in Bytes:"+publicMPIs[1].getByteLength());
    var req = { 
      ACTION: "DSASign",
		  p: publicMPIs[0],
		  q: publicMPIs[1],
		  g: publicMPIs[2],
		  y: publicMPIs[3],
		  x: secretMPIs[0],
		  m: data,
      hash_algo: hash_algo,
      ts: Date.now()
    }
    Callbacks[req.ts] = callback;
    worker.postMessage(JSON.stringify(req));
		//util.print_debug("signing using DSA\n result:"+util.hexstrdump(result[0])+"|"+util.hexstrdump(result[1]));
		//return result[0]+result[1];
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
			logger.debug("signing with Elgamal is not defined in the OpenPGP standard.");
			return null;
	default:
		return null;
	}	
}

exports.asymetricEncrypt = openpgp_crypto_asymetricEncrypt;
exports.asymetricDecrypt = openpgp_crypto_asymetricDecrypt;
exports.signData = openpgp_crypto_signData;
exports.verifySignature = openpgp_crypto_verifySignature;

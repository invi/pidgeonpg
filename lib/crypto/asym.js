const PGP = require("pgp/openpgpdefs");
const logger = require('util/logger').create('crypto.js');
const g4bcrypto = require("crypto/asymmetric/g4bcrypto");
const {hashData} = require('crypto/hash.js');
const misc = require('util/misc');
const {util} = require("crypto/util");
const base64Decode = require("api-utils/base64").decode;
const base64Encode = require("api-utils/base64").encode;
const der = require('encode/der');
const pkcs1 = require("encode/pkcs1");
const {domcrypt} = require('crypto/asymmetric/domcrypt');
const {Ski} = require('crypto/ski');

/**
 * ASN1 object identifiers for hashes (See RFC4880 5.2.2)
 */
var hash_headers = new Array();
hash_headers[1] = [0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10];
hash_headers[3] = [0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x24,0x03,0x02,0x01,0x05,0x00,0x04,0x14];
hash_headers[2] = [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14];
hash_headers[8] = [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20];
hash_headers[9] = [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30];
hash_headers[10] = [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40];
hash_headers[11] = [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1C];

function countProperties(obj) {
  var count = 0;
  for(var prop in obj) {
    if(obj.hasOwnProperty(prop))
      ++count;
  }
  return count;
}

function sessdata_unpad(sessdataPadded64) {
   var sessdataPadded = base64Decode(sessdataPadded64);
   var sessdataLen = sessdataPadded.length;

   while (sessdataPadded.charCodeAt(sessdataLen - 1) == 0 && 
          sessdataLen > 0)
     sessdataLen--;

   return sessdataPadded.substr(0, sessdataLen);
}

exports.decrypt = function(algo, pkey, wrapped_skey, ski, data, callback) {
  var skey = Ski.unwrapSkey(algo, ski, wrapped_skey);

  switch (algo) {
    case PGP.PUBKEY.ALGO.RSA:
    var derseckey = der.encodeSecKey(pkey.concat(skey), algo);
    domcrypt.decrypt(base64Encode(data[0].substr(2)),
                     derseckey,
                     function(paddedData64) {
                       var sessdata = sessdata_unpad(paddedData64);
                       callback(sessdata);
                     });
    break;
    case PGP.PUBKEY.ALGO.ELGAMAL_E:
    var mpi_data = [];
    mpi_data[0] = misc.stohex(data[0].substr(2));
    mpi_data[1] = misc.stohex(data[1].substr(2));

    var publickey_MPIs = [];
    for (var i=0;i<pkey.length;i++)
      publickey_MPIs.push(misc.stohex(pkey[i].substr(2)));

    var secretkey_MPIs = [];
    for (var i=0;i<skey.length;i++)
      secretkey_MPIs.push(misc.stohex(skey[i].substr(2)));

    g4bcrypto.asymetricDecrypt(algo, publickey_MPIs, secretkey_MPIs, mpi_data,
                               function(_sessdata) {
                                 var sessdata = pkcs1.eme_decode(_sessdata, pkey[0].length - 2)
                                 callback(sessdata);
                               });

    break;
    default:
    throw new Error("Invalid decryption algo: " + algo);
  }
}

exports.sign = function(digest_algo, algo, pkey, wrapped_skey, ski, md, callback) {
  var skey = Ski.unwrapSkey(algo, ski, wrapped_skey);
  switch(algo) {
    case PGP.PUBKEY.ALGO.DSA:
      if (pkey[0].length > 256) {
        var hashed_md = hashData(digest_algo, md);
        var msg_MPIs = [],
            publickey_MPIs = [];

        var secretkey_MPIs = [];
        for (var i=0;i<skey.length;i++)
          secretkey_MPIs.push(misc.stohex(skey[i].substr(2)));
        for (var i=0; i<pkey.length; i++)
          publickey_MPIs.push(misc.stohex(pkey[i].substr(2)));
        g4bcrypto.signData(digest_algo, algo, publickey_MPIs, secretkey_MPIs, hashed_md, function(result) {
          callback(hashed_md, result);
        });

      } else {
        var hashed_md = hashData(digest_algo, md);
        var hash_encoded = hashed_md;
        var derseckey = der.encodeSecKey(pkey.concat(skey), algo);
        var derpubkey = der.encodePubKey(pkey, algo);
        var publicValue = der.encodeInteger(pkey[3]);
        domcrypt.sign(hash_encoded, derseckey, publicValue, function(sigdata) {
          callback(hashed_md, base64Decode(sigdata));
        });
      }
      break;
    case PGP.PUBKEY.ALGO.RSA:
      var hashed_md = hashData(digest_algo, md);
      var oid = hash_headers[digest_algo];
      var hash_encoded = misc.atos(oid) + hashed_md;
      var derseckey = der.encodeSecKey(pkey.concat(skey), algo);
      var derpubkey = der.encodePubKey(pkey, algo);
      domcrypt.sign(hash_encoded, derseckey, "", function(sigdata) {
        callback(hashed_md, base64Decode(sigdata));
      });
      break;
    default:
      throw new Error("INV_SIGNING_ALGO");
  }
}

exports.encrypt = function(algo, pkey, data, callback) {
  switch(algo) {
    case PGP.PUBKEY.ALGO.RSA:
    var derpubkey = der.encodePubKey(pkey, algo);
    domcrypt.encrypt(base64Encode(data), derpubkey, function(encrypted_data) {
      callback([base64Decode(encrypted_data)]);
    });
    break;
    case PGP.PUBKEY.ALGO.ELGAMAL_E:
    var publickey_MPIs = [];
    for (var i=0;i<pkey.length;i++)
      publickey_MPIs.push(misc.stohex(pkey[i].substr(2)));
    var msg_MPIs = misc.stohex(pkcs1.eme_encode(data, pkey[0].length - 2));

    g4bcrypto.asymetricEncrypt(algo, publickey_MPIs,  msg_MPIs, 
                               function(encrypted_data_mpis) {
      var encrypted_data = [ ];
      encrypted_data[0] = encrypted_data_mpis[0].substr(2);
      encrypted_data[1] = encrypted_data_mpis[1].substr(2);
      callback(encrypted_data);
    });
    break;
    default:
    throw new Error("Invalid encryption algo:" + algo);
  }
};

exports.verify = function(algo, digest_algo, sigmpis, pubkey, md, callback) {
  switch(algo)
  {
    case PGP.PUBKEY.ALGO.RSA:
    var hash_data = hashData(digest_algo, md);
    var oid = hash_headers[digest_algo];
    var hash_encoded = misc.atos(oid) + hash_data;
    var derpubkey = der.encodePubKey(pubkey, algo);
    logger.debug(derpubkey);
    domcrypt.verify(hash_encoded, sigmpis[0].substr(2),  derpubkey, function(isValid) {
      logger.debug(misc.stohex(hash_encoded));
      callback(isValid);
    });
    break;
    case PGP.PUBKEY.ALGO.DSA:
    if (pubkey[0].length > 256) {
      var msg_MPIs = [],
          publickey_MPIs = [];
  
      for (var i=0; i<sigmpis.length; i++)
        msg_MPIs.push(misc.stohex(sigmpis[i].substr(2)));
      for (var i=0; i<pubkey.length; i++)
        publickey_MPIs.push(misc.stohex(pubkey[i].substr(2)));
  
      g4bcrypto.verifySignature(algo, digest_algo,  msg_MPIs, publickey_MPIs, md, callback);
    }
    else { 
      var msg_MPIs = sigmpis[0].substr(2) + sigmpis[1].substr(2);
      var derpubkey = der.encodePubKey(pubkey, algo);
      var hash_data = hashData(digest_algo, md);
      hash_data = hash_data.substr(hash_data.length-20);
      domcrypt.verify(hash_data, msg_MPIs, derpubkey, function(isValid) {
        callback(isValid);
      });
    }
    break;
    default:
    throw new Error("INV_VERIFY_ALGO");
  }
};

function check_keyLength(keyType, keypairBits) {
  switch(keyType) {
    case PGP.PUBKEY.ALGO.RSA:
      switch (keypairBits) {
        case 1024:
        case 2048:
        case 4096:
        break;
        default:
        throw new Error("INV_ALGO_BITLENGTH");
      }
      break;
    case PGP.PUBKEY.ALGO.DSA:
      switch (keypairBits) {
        case 1024:
        break;
        default:
        throw new Error("INV_ALGO_BITLENGTH");
      }
      break;
    case PGP.PUBKEY.ALGO.ELGAMAL_E:
      switch (keypairBits) {
        case 1024:
        break;
        default:
        throw new Error("INV_ALGO_BITLENGTH");
      }
      break;
    default:
      throw Error("INV_PUBKEY_ALGO");
  }
}

exports.generateKeypair = function(keyType, keypairBits, primarySki, callback) {
  domcrypt.generateKeypair(keyType, keypairBits, function(newkey) {
    try {
      if (!(countProperties(newkey.privKey))) throw new Error("Error generating key pair");

      var byteLen = keypairBits / 8;
      var unwrapped_skey = [], skey = [], pkey = [];
      var fields = newkey.privKey;
      switch(keyType) {
        case PGP.PUBKEY.ALGO.RSA:
        pkey[0] = misc.addmpi_len(base64Decode(fields.n));
        pkey[1] = misc.addmpi_len(base64Decode(fields.e));
        unwrapped_skey[0] = misc.addmpi_len(base64Decode(fields.d));
        unwrapped_skey[1] = misc.addmpi_len(base64Decode(fields.p));
        unwrapped_skey[2] = misc.addmpi_len(base64Decode(fields.q));
        unwrapped_skey[3] = misc.addmpi_len(base64Decode(fields.u));
        break;
        case PGP.PUBKEY.ALGO.ELGAMAL_E:
        pkey[0] = misc.addmpi_len(base64Decode(fields.p));
        pkey[1] = misc.addmpi_len(base64Decode(fields.g));
        pkey[2] = misc.addmpi_len(base64Decode(fields.y));
        unwrapped_skey[0] = misc.addmpi_len(base64Decode(fields.x));
        break;
        case PGP.PUBKEY.ALGO.DSA:
        pkey[0] = misc.addmpi_len(base64Decode(fields.p));
        pkey[1] = misc.addmpi_len(base64Decode(fields.q));
        pkey[2] = misc.addmpi_len(base64Decode(fields.g));
        pkey[3] = misc.addmpi_len(base64Decode(fields.y));
        unwrapped_skey[0] = misc.addmpi_len(base64Decode(fields.x));
        break;
        default:
        throw Error("Invalid public key algo: " + keyType);
        break;
      }
      var {skey, ski} = Ski.generate(unwrapped_skey, primarySki);
      callback(null, pkey, skey, ski); 
    } catch (err) { callback(err); }
  });
}


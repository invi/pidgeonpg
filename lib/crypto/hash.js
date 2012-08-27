const PGP = require("pgp/openpgpdefs");
const {sha160, sha256} = require("crypto/hash/sha");
const misc = require('util/misc');

exports.hashData = function(algo, data) {
  var hashdata = null;
  switch (algo) {
    case PGP.HASH.MD5:        
    throw new Error("MD5 hash function not implemented");
    break;
    case PGP.HASH.SHA1:
    hashdata = sha160(misc.stoa(data));
    break;
    case PGP.HASH.RIPEMD160:
    throw new Error("RIPEMD160 hash function not implemented");
    break;
    case PGP.HASH.SHA256:
    hashdata = sha256(misc.stoa(data));
    break;
    case PGP.HASH.SHA384:
    throw new Error("SHA384 hash function not implemented");
    break;
    case PGP.HASH.SHA512:
    throw new Error("SHA512 hash function not implemented");
    break;
    case PGP.HASH.SHA224:
    throw new Error("SHA224 hash function not implemented");
    break;
    default:
    console.trace();
    throw new Error("Unkown hash function: " + algo);
  }
  return hashdata;
}


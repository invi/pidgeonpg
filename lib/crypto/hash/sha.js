const {Cc, Ci} = require("chrome");

function sha256(bytearray) 
{
  let hasher = Cc["@mozilla.org/security/hash;1"]
                 .createInstance(Ci.nsICryptoHash);

  hasher.init(hasher.SHA256);
  hasher.update(bytearray, bytearray.length);

  let rawHash = hasher.finish(false);

  return rawHash;
}

function sha160(bytearray) 
{
  let hasher = Cc["@mozilla.org/security/hash;1"]
                 .createInstance(Ci.nsICryptoHash);

  hasher.init(hasher.SHA1);
  hasher.update(bytearray, bytearray.length);

  let rawHash = hasher.finish(false);

  return rawHash;
}

exports.sha160 = sha160;
exports.sha256 = sha256;


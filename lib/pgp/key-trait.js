// # KeyTrait
// 
// Class mix of [BaseTrait](key-trait.html) and [FormatTrait](key-format.html)
const misc = require("util/misc");
const PGP = require("pgp/openpgpdefs");
const {hashData} = require("crypto/hash");
const asymcrypto = require("crypto/asym");
const {Trait} = require('light-traits');
const {BaseTrait} = require('pgp/base-trait');
const {FormatTrait} = require('pgp/format-trait');

// ## Helper functions
// 
// ### getPublicDigest(pk)
//
// Constructs public key/subkey digest
//
// `pk` key/subkey packet serializable object
//
// Returns the message digest as `string`
function getPublicDigest(pk) 
{
  var n = 6;
  var npkey = misc.pubkey_get_npkey(pk.pubkey_algo);

  if (pk.version < 4)
          n+=2;

  var pkey_digest = "";
  for (var i=0;i<npkey;i++)
  {
    pkey_digest += pk.pkey[i]; 
    n += pk.pkey[i].length;
  }

  return String.fromCharCode(0x99) +
         String.fromCharCode(n >> 8) +
         String.fromCharCode(n & 0xff) +
         String.fromCharCode(pk.version) +
         misc.u32_to_string(pk.timestamp) +
         String.fromCharCode(pk.pubkey_algo) + 
         pkey_digest;
}

// ## Key trait to mix
let t = Trait({
  getPacket: Trait.required,
  // ## keytrait.getPacketType()
  getPacketType: function() { return this.getPacket().pkttype },
  // ## keytrait.getPubKey()
  getPubKey: function() { return this.getPacket().pkey },
  // ## keytrait.getSecKey()
  getSecKey: function() { return this.getPacket().skey },
  // ## keytrait.isSecret()
  isSecret: function() { 
    var pkttype = this.getPacketType();
    return (pkttype == PGP.PKT.SECRET_KEY || pkttype == PGP.PKT.SECRET_SUBKEY)
  },
  // ## keytrait.isPublic()
  isPublic: function() { return !this.isSecret() },
  // ## keytrait.getByteLength()
  getByteLength: function() { return this.getPubKey()[0].length - 2 },
  // ## keytrait.getKeyId()
  getKeyId: Trait.required, //function() { return this.getPacket().keyid },
  // ## keytrait.getKeyIdStr()
  getKeyIdStr: function() { return misc.stohex(this.getKeyId()).toUpperCase() },
  // ## keytrait.getFingerprintStr()
  getFingerprintStr: function() { 
    var fp = misc.stohex(this.getPacket().fingerprint).toUpperCase() 
    var ret = "";
    for (var i=0;i<fp.length/8;i++) 
      ret += " " + fp.substr(i*8,8);
    return ret.substr(1);
  },
  // ## keytrait.getShortKeyIdStr()
  getShortKeyId: function() { return this.getKeyIdStr().slice(8,16) },
  // ## keytrait.getAlgo()
  getAlgo: function() { return this.getPacket().pubkey_algo },
  getAlgoStr: function() { return PGP.PUBKEY_ALGOS[this.getPacket().pubkey_algo] },
  // ## keytrait.getDigest()
  getDigest: function() { return getPublicDigest(this.getPacket()) },
  addPacket: Trait.required,
  // ## key.isProtected()
  //
  // Returns `boolean` as true if key material is encrypted
  isProtected : function() { 
    return this.getPacket().ski.usage ? true : false 
  },
  // ## key.isExpired()
  //
  // Returns `boolean` as true key has expired
  isExpired : function() {
    if (this.getPacket().timestamp == this.getPacket().expiredate) {
      return false;
    } else {
      var ts = Math.ceil(new Date().getTime()/1000);
      var expiredate = this.getPacket().expiredate;
      return !!(expiredate && (ts > expiredate));
    }
  },
  getSki: function() {
    return this.getPacket().ski || {};
  },
  setSki: function(ski) {
    this.getPacket().ski = ski;
  },
  encrypt: function(sessionkeypacket, callback) 
  {
    asymcrypto.encrypt(this.getAlgo(), this.getPubKey(), 
                   sessionkeypacket,function(encryptedsessionkey) {
                     callback(encryptedsessionkey);
                   }); 
  },
  decrypt: function(encryptedsessionkey, callback) 
  {
    asymcrypto.decrypt(this.getAlgo(), this.getPubKey(), this.getSecKey(), this.getSki(), 
                   encryptedsessionkey, function(sessdata) { 
                     callback(sessdata);
                   });
  },
  getFormattedPacket: function() {
    var key = {
      id: this.getKeyIdStr(),
      length: (this.getByteLength()*8).toString(),
      algo: this.getAlgoStr(),
      secret: this.isSecret(),
      short_id: this.getShortKeyId(),
      creation_date: this.getCreationDate(),
      expiration_date: this.getExpirationDate(),
      fingerprint: this.getFingerprintStr(),
      revoked: this.isRevoked(),
      expired: this.isExpired(),
      verified: this.isVerified(),
      protected: this.isProtected(),
      valid: this.isValid(),
      ringstatus: this.status.ringstatus,
    }
    return key;
  },
  // keytrait.hash_public_key()
  //
  // Hashes a key packet object
  hash_public_key: function() {
    var md = getPublicDigest(this.getPacket())
  	var hashed_md = hashData(PGP.HASH.SHA1, md);
    this.getPacket().keyid = hashed_md.substr(12, 4) + hashed_md.substr(16, 4);
    this.getPacket().keyid_str = this.getKeyIdStr();
    this.getPacket().fingerprint = hashed_md;
  },
  isEncryptionAlgo: function() {
    switch(this.getAlgo()) {
      case PGP.PUBKEY.ALGO.RSA:
      case PGP.PUBKEY.ALGO.ELGAMAL_E:
      return true;
      default:
      return false;
    }
  },
  isSignatureAlgo: function() {
    switch(this.getAlgo()) {
      case PGP.PUBKEY.ALGO.RSA:
      case PGP.PUBKEY.ALGO.ELGAMAL_E:
      return true;
      default:
      return false;
    }
  },
  verify: Trait.required,
  updateStatus: Trait.required
});

exports.KeyTrait = Trait.compose(BaseTrait, FormatTrait, t);

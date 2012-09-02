const PGP = require('pgp/openpgpdefs.js');
const logger = require('util/logger').create("signature.js");
const misc = require('util/misc.js');
const asymcrypto = require("crypto/asym");
const base64Decode = require("api-utils/base64").decode;
const base64Encode = require("api-utils/base64").encode;
const {hashData} = require("crypto/hash");
const {write_packet_header} = require("pgp/export");
const {getStr} = require('util/lang');
const {Trait} = require('light-traits');
const {BaseTrait} = require('pgp/base-trait');
const {FormatTrait} = require('pgp/format-trait');
logger.stdout = true;

/**
 * Checks status of Public Key
 * @function 
 * @param pk Public Key packet
 * @param sig Self Signature packet
 * XXX Not used
 */
function _do_check_messages(kb, sig) {
  var cur_time;
  var pk = kb.kpkt;

  if( pk.timestamp > sig.timestamp )
  {
	  d = pk.timestamp - sig.timestamp;
    logger.error(d==1 ? "public key %s is %lu second newer than the signature"
	                    : "public key %s is %lu seconds newer than the signature",
	                      kb.getKeyIDStr(), d);

	  return PGP.ERR.TIME_CONFLICT; /* pubkey newer than signature */
  }

  cur_time = parseInt(new Date().getTime() / 1000);

  if( pk.timestamp > cur_time )
  {
    d = pk.timestamp - cur_time;
    logger.error( d==1 ? "key %s was created %lu second\
  	                     in the future (time warp or clock problem)"
  	                   : "key %s was created %lu seconds\
	                       in the future (time warp or clock problem)",
                         kb.getKeyIDStr(),d );
    return PGP.ERR.TIME_CONFLICT;
  }

  if( pk.has_expired || (pk.expiredate && pk.expiredate < cur_time)) 
  {
    logger.info("NOTE: signature key %s expired %s",
                kb.getKeyIDStr(), 
                new Date(pk.expiredate * 1000));
    pk.has_expired = true;
  }

  if (pk.flags.revoked)
  {
	  logger.info("NOTE: signature key %s has been revoked",
                pk.getKeyIDStr());
  }
  return 0;
}

/*
  Wraps signature subpacket with encoded length
  @param {integer} Type
  @param {string} Data string
  @retuns {string} Wrapped string
  XXX Missing long length encodings
*/
function write_sigsubpkt(type, str) {
  return String.fromCharCode(str.length + 1) + 
         String.fromCharCode(type) + str;
}

function write_sig_unhash(sig) {
  return misc.stoa(write_sigsubpkt(PGP.SIGSUBPKT.ISSUER, sig.pkt.keyid));
}

function write_sig_hash(sig) {
  var ret;
  switch(sig.pkt.sig_class) {
    case PGP.SIGCLASS.KEY_SIG:
    var expireseconds = sig.pkt.expiredate - sig.pkt.timestamp;
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    ret += misc.atos([2,27,3]);
    ret += write_sigsubpkt(PGP.SIGSUBPKT.SIG_EXPIRE, misc.u32_to_string(expireseconds));
    ret += misc.atos([6,11,9,8,7,3,2,6,21,8,2,9,10,11,4,22,2,3,1,2,30,1,2,23,128]);
    break;

    case PGP.SIGCLASS.SUBKEY_SIG:
    var expireseconds = sig.pkt.expiredate - sig.pkt.timestamp;
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp)) +
          write_sigsubpkt(PGP.SIGSUBPKT.KEY_FLAGS, String.fromCharCode(12)) +
          write_sigsubpkt(PGP.SIGSUBPKT.SIG_EXPIRE, misc.u32_to_string(expireseconds));
    break;

    case PGP.SIGCLASS.CANONICAL:
    case PGP.SIGCLASS.BINARY:
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    break;

    case PGP.SIGCLASS.KEY_REV:
    case PGP.SIGCLASS.SUBKEY_REV:
    case PGP.SIGCLASS.UID_REV:
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    var revoc_subpacket = String.fromCharCode(sig.pkt.revoc_reason) + sig.pkt.revoc_comment;
    ret += write_sigsubpkt(PGP.SIGSUBPKT.REVOC_REASON, revoc_subpacket);
    ret += write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    //ret += write_sigsubpkt(PGP.SIGSUBPKT.ISSUER, sig.keyid);
    break;

    case PGP.SIGCLASS.UID_SIG:
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    ret += write_sigsubpkt(PGP.SIGSUBPKT.ISSUER, sig.pkt.keyid);
    break;

    default:
    throw new Error("PGP.ERR.BAD_SIGCLASS");
  }
  return misc.stoa(ret);
}

/**
 * Creates an instance of Signature.
 *
 * @constructor
 * @param {object} sigpacket Object representing the signature data packet
 * @param {Key} key Key object used for the signature
 */
function Signature() {
  var sig = Trait.compose(BaseTrait, FormatTrait).create(Signature.prototype);
  sig.key = null;
  sig.holdingkey = null;
  sig._sig = {
    pkt: { pkttype: PGP.PKT.SIGNATURE, data: [], version: 4},
    revsigs: [],
  }
  sig.status = {
    valid: false, 
    verified: false, 
    revoked: false
  };
  return sig;
}

Signature.load = function(_sig, holdingkey, verified) {
  var sig = new Signature();
  try {
    sig._sig = _sig;
    sig.holdingkey = holdingkey;
    if (sig.isSelf()) sig.key = holdingkey;
    if (verified && verified == true) sig.status.valid = true;
  } catch(err) {
    logger.error(err);
  } 
  return sig;
}

/*
 *  @param {object} sigpacket Object representing the signature data packet
 *  @param {Key} key Key object used for the signature
 */
//Signature.create = function(pars, callback) {
//  try {
//    if (!pars.hasOwnProperty("sig_class")) throw new Error("PGP.ERR.NO_SIGCLASS");
//    if (typeof key == "undefined") throw new Error("PGP.ERR.NO_KEY");
//    if (!key.isSecret()) throw new Error("Error creating signature. Secret key required"); 
//    var ts = Math.floor(Date.now() / 1000);
//    var sig_packet = {
//      pkttype: PGP.PKT.SIGNATURE,
//      version: 4,
//      sig_class: pars.sig_class,
//      revoc_reason: pars.revoc_reason,
//      revoc_comment: pars.revoc_comment,
//      pubkey_algo: key.getAlgo(),
//      digest_algo: PGP.HASH.SHA1,
//      flags: {"exportable":1, "revocable":1},
//      hashed: { },
//      unhashed: { },
//      timestamp: ts,
//      expiredate: ts + pars.expireseconds,
//      keyid: key.getKeyId(),
//      data: [ ],
//    }
//    sig_packet.hashed.data = write_sig_hash(sig_packet);
//    sig_packet.unhashed.data = write_sig_unhash(sig_packet);
//
//    var sig = new Signature();
//    sig._sig.pkt = sig_packet;
//    sig.key = key;
//    sig.signData(pars.data, function(err) { 
//      if (err) callback(err);
//      else callback(null, sig);
//    });
//  } catch(err) { callback(err) }
//}

/**
 * @returns {boolean} True if this isn't a user id self-signature.
 */
Signature.prototype.isNonSelf = function() {
  return this.holdingkey.getKeyId() != this.getKeyId();
};

/**
 * @return {boolean} True if this is a user id self-signature
 */
Signature.prototype.isUserIdSig = function() {
  return ((this._sig.pkt.sig_class & ~3) == PGP.SIGCLASS.UID_SIG);
};

/**
 * @return {boolean} True if this is a user id self-signature
 */
Signature.prototype.isCertSig = function() {
  return (((this._sig.pkt.sig_class & ~3) == PGP.SIGCLASS.UID_SIG) || 
            this._sig.pkt.sig_class == PGP.SIGCLASS.DIRECT_SIG);
};

/**
 * @return {boolean} True if this is a user id revocation signature
 */
Signature.prototype.isUserIdRev = function() {
  return (this._sig.pkt.sig_class == PGP.SIGCLASS.UID_REV);
};

/**
 * @return {boolean} True if this is key signature
 */
Signature.prototype.isKeySig = function() {
  return (this._sig.pkt.sig_class == PGP.SIGCLASS.KEY_SIG);
};

/**
 * @return {boolean} True if this is subkey signature
 */
Signature.prototype.isSubkeySig = function() {
  return (this._sig.pkt.sig_class == PGP.SIGCLASS.SUBKEY_SIG);
};

/**
 * @return {boolean} True if this is subkey revocation signature
 */
//Signature.prototype.isSubkeyRev= function() {
//  return (this._sig.sig_class == PGP.SIGCLASS.SUBKEY_REV);
//};

/**
 * @return {boolean} True if this is key revocation signature
 */
Signature.prototype.isKeyRev = function() {
  return ((this._sig.pkt.sig_class == PGP.SIGCLASS.KEY_REV) ||
           this._sig.pkt.sig_class == PGP.SIGCLASS.SUBKEY_REV);
};

/**
 * @returns {boolean} True if this is a user id self-signature.
 */
Signature.prototype.isSelf = function() {
  return this.getKeyId() == this.holdingkey.getKeyId();
};

/**
 * @returns {string} Return Key id string data.
 */
Signature.prototype.getKeyId = function() {
  return this._sig.pkt.keyid;
};

/**
 * @returns {number} Packet type
 */
Signature.prototype.getPacketType = function() {
  return this._sig.pkt.pkttype;
};

/**
 * @returns {object} Signature serializable data
 */
Signature.prototype.getPacket = function() {
  return this._sig.pkt;
}


/**
 * Sets signature raw data value
 * @param {string} sigdata  Data string
 */
Signature.prototype.setData = function(sigdata) {
  if (this.key.getAlgo() == PGP.PUBKEY.ALGO.DSA) {
    var d1 = sigdata.substr(0, sigdata.length / 2);
    var d2 = sigdata.substr(sigdata.length / 2);
    this._sig.pkt.data[0] = misc.addmpi_len(d1);
    this._sig.pkt.data[1] = misc.addmpi_len(d2);
  } else {
    var len = sigdata.length;
    len *= 8; //in bits
    this._sig.pkt.data[0] = misc.atos([len >> 8, len & 0xff ]);
    this._sig.pkt.data[0] += sigdata;
  }
}

/**
 * Sets signature digest start
 * @param {array} digest_start Two first hash values as byte array 
 */
Signature.prototype.setDigestStart = function(digest_start) {
  this._sig.pkt.digest_start = digest_start;
}

/**
 * Performs a signature of the data and this signature
 *
 * @param {function} cipher_fnc Cipher hash function
 * @param {function} crypto_fnc Assymetric crypto function
 * @param {string} data Data string to sign
 * @param {function} callback Callback after signing
 */
Signature.prototype.signData = function(data, callback) {
  var self = this;
  var md = data + this.getDigest();
  var key = this.key;
  logger.debug("Issuer key: " + this.key.getKeyIdStr());
  logger.debug("Holding key: " + this.getKeyId());
  asymcrypto.sign(this._sig.pkt.digest_algo, key.getAlgo(), key.getPubKey(), key.getSecKey(),
              key.getSki(), md, function(hashed_md, sigdata) {
                try  { 
                  self.setDigestStart([hashed_md.charCodeAt(0), 
                                       hashed_md.charCodeAt(1)]);
                  self.status.valid = true;
                  self.status.verified = true;
                  self.setData(sigdata);
                  callback(null);
                } catch(err) {
                  callback(err);
                }
              });
}

Signature.generate = function(pars, callback) {
  try {
    var ts = Math.floor(Date.now() / 1000); 
    var sig = new Signature();
    sig._sig.pkt.sig_class = pars.sig_class;
    sig._sig.pkt.digest_algo = PGP.HASH.SHA1;
    sig._sig.pkt.revoc_reason = pars.revoc_reason;
    sig._sig.pkt.revoc_comment = pars.revoc_comment;
    sig._sig.pkt.flags = {"exportable":1, "revocable":1};
    sig._sig.pkt.keyid = pars.key.getKeyId();
    sig._sig.pkt.timestamp = pars.timestamp || ts;
    sig._sig.pkt.expireseconds = pars.expireseconds || 0;
    sig._sig.pkt.expiredate = pars.expiredate;
    sig._sig.pkt.pubkey_algo = pars.key.getAlgo(),
    sig._sig.pkt.hashed = {};
    sig._sig.pkt.hashed.data = write_sig_hash(sig._sig);
    sig._sig.pkt.unhashed = {};
    sig._sig.pkt.unhashed.data = write_sig_unhash(sig._sig);

    sig.key = pars.key;
    sig.holdingkey = pars.holdingkey || pars.key;

    sig.logger = logger;
    sig.signData(pars.data, function(err) {
      if (err) callback(err);
      else callback(null, sig);
    });
  } catch(err) { logger.error(err) };
}

/**
 * Performs a hash of the key and signature
 *
 * @param {function} cipher_fnc Cipher hash function
 * @returns {string} Hashed data string
 */
Signature.prototype.hash = function(cipher_fnc) {
  var md = this.key.getDigest() + this.getDigest(); 

  //XXX cipher
  var hashed_md = cipher_fnc(misc.stoa(md));

  //unhashed sig
  this.setDigestStart([hashed_md.charCodeAt(0), 
                       hashed_md.charCodeAt(1)]);

  var oid = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
  return misc.atos(oid) + hashed_md;
}

/**
 * Performs a hash of the data argument and signature
 *
 * @param {function} cipher_fnc Cipher hash function
 * @param {string} data Data to hash
 * @returns {string} Hashed data string
 */
Signature.prototype.hashData = function(data) {
  var md = data + this.getDigest();

  //XXX cipher
  var hashed_md = hashData(this._sig.digest_algo, md);

  ////unhashed sig
  this.setDigestStart([hashed_md.charCodeAt(0), 
                       hashed_md.charCodeAt(1)]);

  var oid = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
  return misc.atos(oid) + hashed_md;
}

/**
 * Generates the message digest for the signature 
 *
 * @returns {string} Message digest string data
 */
Signature.prototype.getDigest = function() {
  var md = "", n = 0, pkt = this._sig.pkt;

  md += String.fromCharCode(pkt.version) +
        String.fromCharCode(pkt.sig_class) +
        String.fromCharCode(pkt.pubkey_algo) +
        String.fromCharCode(pkt.digest_algo);

  if (pkt.hashed) {
    n = pkt.hashed.data.length;
    md += misc.u16_to_string(n);
    md += misc.atos(pkt.hashed.data);
    n += 6;
  } else {
	  /* Two octets for the (empty) length of the hashed
             section. */
    //XXX not used
    md += String.fromCharCode(0);
    md += String.fromCharCode(0);
	  n = 6;
	}
 	/* add some magic */
  md += String.fromCharCode(pkt.version) +
        String.fromCharCode(0xff) +
        misc.u32_to_string(n);

  return md;
}

/**
 * Performs a verification of the data and this signature
 *
 * @param {function} cipher_fnc Cipher hash function
 * @param {function} crypto_fnc Assymetric crypto function
 * @param {string} data Data string to sign
 * @param {function} callback Callback after signing
 */
Signature.prototype.verifyData = function(data, callback) {
  try {
    var self = this;
    var md = data + this.getDigest();
    asymcrypto.verify(this.key.getAlgo(), this._sig.pkt.digest_algo, this._sig.pkt.data, 
                  this.key.getPubKey(), md, function(isValid) {
      try  { 
        self.status.valid = isValid;
        self.status.verified = true;
        callback(null, isValid);
      } catch(err) { callback(err);}
    });
  } catch(err) { callback(err) };
}

/**
 * Performs a verification of the key and signature
 *
 * @param {function} cipher Initialized crypto module
 * @param {function} callback Callback after signing
 */
Signature.prototype.verify = function(callback) {
  this.verifyData(this.key.getDigest(), callback);
}

/**
 * @returns {boolean} True if signature is valid
 */
Signature.prototype.isValid = function() {
  return this.status.valid;
}

/**
 * @returns {object} Signature serializable data
 */
Signature.prototype.serialize = function() {
  return this._sig.pkt;
}

Signature.prototype.getKeyFlags = function() {
  return this._sig.pkt.key_flags;
}

Signature.prototype.hasEncryptionFlag = function() {
  return this.getKeyFlags() & (PGP.KEY_FLAGS.CS | PGP.KEY_FLAGS.EC); 
}

Signature.prototype.getIssuerKeyId = function() {
  return this._sig.pkt.keyid;
}

Signature.prototype.getIssuerKeyIdStr = function() {
  return misc.stohex(this._sig.pkt.keyid).toUpperCase();
}

Signature.prototype.getSigClassStr = function() {
  return PGP.SIGCLASS_STR[this._sig.pkt.sig_class];
}

Signature.prototype.getFormatted = function() {
  return this.getFormattedPacket();
}

Signature.prototype.getRevocReason = function() {
  switch(parseInt(this._sig.pkt.revoc_reason)) {
    case 0:
      return getStr("rev0x00");
    case 1:
    case 2:
    case 3:
      return this.isKeyRev() ? getStr("rev0x" + ("0" + this._sig.pkt.revoc_reason.toString(16).slice(-2))) : 
                               getStr("INV_KEYREV");
    case 32:
      return this.isUserIdRev() ? getStr("rev0x20") : getStr("INV_CERTREV");
    default:
      if (this._sig.pkt.revoc_reason >= 100 && this._sig.pkt.revoc_reason <= 110) 
        return getStr("rev0x64");
      else
        return getStr("REV_UNKNOWN");
  }
}

Signature.prototype.getFormattedPacket = function() {
  var sig = {
    id: this.getIssuerKeyIdStr(),
    sig_class: this.getSigClassStr(),
    revoked: this.isRevoked(),
    expired: this.isExpired(),
    verified: this.isVerified(),
    keyflags: this.getKeyFlagsStr(),
    hash_algos: this.getHashAlgosStr(),
    sym_algos: this.getSymAlgosStr(),
    revoc_reason: this.getRevocReason(),
    revoc_comment: this._sig.pkt.revoc_comment,
    creation_date : this.getCreationDate(),
    expiration_date: this.getExpirationDate(),
    ringstatus: this.status.ringstatus,
    valid: this.isValid(),
  }
  return sig;
}

Signature.prototype.isExpired = function() {
  if (this.getPacket().timestamp == this.getPacket().expiredate) {
    return false;
  } else {
    var ts = Math.ceil(new Date().getTime()/1000);
    var expiredate = this.getPacket().expiredate;
    return !!(expiredate && (ts > expiredate));
  }
}

Signature.prototype.getKeyFlagsStr = function() {
  var flags = this.getKeyFlags(),
      ret = [];
  if (flags & PGP.KEY_FLAGS.CS) ret.push(getStr("KF_CS"));
  if (flags & PGP.KEY_FLAGS.SD) ret.push(getStr("KF_SD"));
  if (flags & PGP.KEY_FLAGS.EC) ret.push(getStr("KF_EC"));
  if (flags & PGP.KEY_FLAGS.ES) ret.push(getStr("KF_ES"));
  if (flags & PGP.KEY_FLAGS.SM) ret.push(getStr("KF_SM"));
  if (flags & PGP.KEY_FLAGS.AU) ret.push(getStr("KF_AU"));
  if (flags & PGP.KEY_FLAGS.MP) ret.push(getStr("KF_MP"));
  return ret;
}

Signature.prototype.getHashAlgosStr = function() {
  var ret = [];
  var hashes = this._sig.pkt.pref_hash;
  if (typeof hashes == "undefined") return ret;

  for (var i=0;i<hashes.length;i++) {
    if (hashes[i] in PGP.HASH_INV) 
      ret.push(PGP.HASH_INV[hashes[i]]);
    else
      ret.push(getStr("UNK_HASH", hashes[i]))
  }
  return ret;
}

Signature.prototype.getSymAlgosStr = function() {
  var ret = [];
  var symalgos = this._sig.pkt.pref_sym;
  if (typeof symalgos == "undefined") return ret;

  for (var i=0;i<symalgos.length;i++) {
    if (symalgos[i] in PGP.CIPHER.ALGO_INV) 
      ret.push(PGP.CIPHER.ALGO_INV[symalgos[i]]);
    else
      ret.push(getStr("UNK_HASH", symalgos[i]))
  }
  return ret;
}

//        Ver 4 - new
//        Sig type - Positive certification of a User ID and Public Key packet(0x13).
//        Pub alg - RSA Encrypt or Sign(pub 1)
//        Hash alg - SHA1(hash 2)
//        Hashed Sub: signature creation time(sub 2)(4 bytes)
//                Time - Mon Jan 23 05:41:12 CET 2012
//        Hashed Sub: key flags(sub 27)(1 bytes)
//                Flag - This key may be used to certify other keys
//                Flag - This key may be used to sign data
//        Hashed Sub: key expiration time(sub 9)(4 bytes)
//                Time - Tue Jan 22 05:41:12 CET 2013
//        Hashed Sub: preferred symmetric algorithms(sub 11)(5 bytes)
//                Sym alg - AES with 256-bit key(sym 9)
//                Sym alg - AES with 192-bit key(sym 8)
//                Sym alg - AES with 128-bit key(sym 7)
//                Sym alg - CAST5(sym 3)
//                Sym alg - Triple-DES(sym 2)
//        Hashed Sub: preferred hash algorithms(sub 21)(5 bytes)
//                Hash alg - SHA256(hash 8)
//                Hash alg - SHA1(hash 2)
//                Hash alg - SHA384(hash 9)
//                Hash alg - SHA512(hash 10)
//                Hash alg - SHA224(hash 11)
//        Hashed Sub: preferred compression algorithms(sub 22)(3 bytes)
//                Comp alg - ZLIB <RFC1950>(comp 2)
//                Comp alg - BZip2(comp 3)
//                Comp alg - ZIP <RFC1951>(comp 1)
//        Hashed Sub: features(sub 30)(1 bytes)
//                Flag - Modification detection (packets 18 and 19)
//        Hashed Sub: key server preferences(sub 23)(1 bytes)
//                Flag - No-modify
//        Sub: issuer key ID(sub 16)(8 bytes)
//                Key ID - 0xC8EB526B5D35551A
//        Hash left 2 bytes - 1a 85 
//        RSA m^d mod n(4096 bits) - ...

/**
 * @function
 * @returns {string} Binary data string of the signature packet 
 */
Signature.prototype.write_packet = function() {
  var ret = "",
      sigPacket = this.getPacket();
  
  ret += String.fromCharCode(sigPacket.version);
  ret += String.fromCharCode(sigPacket.sig_class); 
  ret += String.fromCharCode(sigPacket.pubkey_algo); 
  ret += String.fromCharCode(sigPacket.digest_algo) ;
  ret += misc.u16_to_string(sigPacket.hashed.data.length); 
  ret += misc.atos(sigPacket.hashed.data); 
  ret += misc.u16_to_string(sigPacket.unhashed.data.length);
  ret += misc.atos(sigPacket.unhashed.data); 
  ret += misc.atos(sigPacket.digest_start); 

  for (var i=0;i<sigPacket.data.length;i++) 
    ret += sigPacket.data[i];

  return misc.write_packet_header(this.getPacketType(), ret.length) + ret;
}

exports.Signature = Signature;

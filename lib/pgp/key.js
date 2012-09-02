// # Key
const PGP = require("pgp/openpgpdefs");
const {Signature} = require('pgp/signature');
const {Subkey} = require('pgp/subkey');
const {UserId} = require('pgp/userid');
const {KeyTrait} = require('pgp/key-trait');
const misc = require('util/misc');
const asymcrypto  = require('crypto/asym');
const {getStr} = require('util/lang');
const Logger = require("util/logger");
const logger = require("util/logger").create("key.js");

// ## Class: Key
// 
function Key() {
  var key = KeyTrait.create(Key.prototype);
  key._key = { 
    pkt: null,
    uids: [ ],       
    subkeys: [ ],  
    revsigs: [ ],
  }

  // Packet Classes Instances
  key.uids = [ ];
  key.subkeys = [ ];
  key.revsigs = [ ];
  key.status = {
    verified: false,
    valid: false,
    revoked: false,
  };
  key.logger = null;

  return key;
}

Key.generate = function(pars, callback) {
  try {
    var keyType = pars.keyType || PGP.ALGO.RSA;
    var subkeyType = pars.subkeyType || keyAlgo;
    var keypairBits = pars.keypairBits || 2048;
    var expireseconds = pars.expireseconds || 0;
    asymcrypto.generateKeypair(keyType, keypairBits, null, function(err, pkey, skey, ski) {
      try {
        if (err) { callback(err); }
        else {
          var ts = Math.floor(Date.now() / 1000); 
          var newkey = new Key();
          newkey._key.pkt = {
            pkttype: PGP.PKT.SECRET_KEY,
            version: 4,
            timestamp: ts,
            expiredate: ts + expireseconds, 
            pubkey_algo: keyType,
            pkey: pkey,
            skey: skey,
            ski: ski,
          };
          newkey.logger = Logger.create("Key.generate");
          newkey.hash_public_key();
          newkey.generateUserId(pars.name, expireseconds, function(err) {
            if (err) callback(err); 
            else
              newkey.generateSubkey(subkeyType, keypairBits, expireseconds, function(err) {
                if (err) callback(err)
                else callback(null, newkey);
              });
          });
        }
      } catch (err) { callback(err); }
    }); 
  } catch (err) { callback(err); }
}

Key.prototype.generateSubkey  = function(algo, keypairBits, expireseconds, callback) {
  var self = this;
  asymcrypto.generateKeypair(algo, keypairBits, this.getSki(), function(err, pkey, skey, ski) {
    try {
      var ts = Math.floor(Date.now() / 1000); 
      var subkey_pkt = {
        pkttype: PGP.PKT.SECRET_SUBKEY,
        timestamp: ts,
        pubkey_algo: algo,
        pkey: pkey,
        skey: skey,
        ski: ski,
        version: 4,
      }
      var subkey = self.addPacket(subkey_pkt);
      subkey.generateSelfSig(expireseconds, function(err, newsig) {
        if (err) callback(err)
        else callback(null, subkey);
      });
    } catch(err) { callback(err); }
  });
}

Key.loadFromPacket = function(pkt, logger) {
  var key = new Key();
  key._key.pkt = pkt;
  key.hash_public_key();
  key.logger = logger;
  return key;
}

// ### Class Method: Key.load(_key, verified)
// 
// * `_key` Object - represents the key from storage data packets
//
// * `verified` Boolean - used when loaded from key ring
// 
// Returns a Key class instance.
Key.load = function(_key, verified) {
  var key = new Key();
  key._key = _key;
  for (var i=0; i<_key.revsigs.length; i++)  {
    var sig = Signature.load(_key.revsigs[i], key, verified);
    key.revsigs.push(sig);
    if (verified) sig.status.valid = true;
  }
  for (var i=0,_uid=_key.uids[i]; i<_key.uids.length; i++)  {
    var uid = UserId.load(_uid, key, verified);
    key.uids.push(uid);
  }
  for (var i=0,_subkey=_key.subkeys[i];i<_key.subkeys.length;i++) {
    var subkey = Subkey.load(_subkey, key, verified);
    key.subkeys.push(subkey);
  }
  key.updateStatus();
  return key;
}

//Key.prototype.addSignature = function(newsig) {
//  var max = null;
//  for (var i=this.selfsigs.length-1;i>=0;i--) 
//    if (newsig._sig.timestamp > sigs[i]._sig.timestamp) 
//      max = i;
//
//  if (max!=null) 
//    sigs.splice(max, 0, newsig);
//  else
//    sigs.push(newsig);
//  return sigs;
//}

// ### key.updateStatus()
// 
// Fills-in the key validity status.


// ### key.addPacket(pkt)
// `pkt` Parsed `object` packet belonging to the key.
// 
// Return the `object` instance of the data packet.
Key.prototype.addPacket = function(pkt) {
  try {
    switch (pkt.pkttype) {
      case PGP.PKT.PUBLIC_SUBKEY:
      case PGP.PKT.SECRET_SUBKEY:
        var subkey = Subkey.load({pkt: pkt}, this)
        this.subkeys.push(subkey);
        this._key.subkeys.push(subkey._subkey);
        return subkey;
      case PGP.PKT.USER_ID:
        var uid = UserId.load({pkt: pkt}, this);
        this.uids.push(uid);
        this._key.uids.push(uid._uid);
        return uid;

      case PGP.PKT.SIGNATURE:
        switch(pkt.sig_class) {
          case PGP.SIGCLASS.SUBKEY_SIG: 
          case PGP.SIGCLASS.SUBKEY_REV: 
          var subkey = this.subkeys[this.subkeys.length-1];
          return subkey.addPacket(pkt);

          case PGP.SIGCLASS.UID_SIG: 
          case PGP.SIGCLASS.CASUAL_SIG: 
          case PGP.SIGCLASS.UID_REV: 
          case PGP.SIGCLASS.KEY_SIG: 
          var uid = this.uids[this.uids.length-1];
          return uid.addPacket(pkt);

          case PGP.SIGCLASS.KEY_REV: 
          var sig = Signature.load({pkt: pkt}, this);
          this._key.revsigs.push(sig._sig);
          this.revsigs.push(sig);
          return sig;

          default:
          throw new Error("Invalid Key signature class: " + pkt.sig_class);
        }
      case PGP.PKT.RING_TRUST:
        throw new Error("Ring trust packet not implemented");

      default:
        throw new Error("Invalid Key packet type: " + pkt.pkttype);
    }
  } catch(err) { logger.error(err); }

  return null;
}

// ### export_pubkey()
//
// Returns the armored public key as `string` .
Key.prototype.export_pubkey = require("pgp/export").export_pubkey;

// ### export_seckey()
// 
// Returns the armored secret key as `string` .
Key.prototype.export_seckey = require("pgp/export").export_seckey

// ### revoke(revoc_reason, revoc_comment, [callback])
// 
// Revokes primary key
Key.prototype.generateRevocation = function(revoc_reason, revoc_comment, callback) {
  try {
    if (this.isRevoked()) throw new Error("Key is already revoked");
    var sig_pars = { sig_class: PGP.SIGCLASS.KEY_REV, 
                     revoc_reason:  revoc_reason, 
                     revoc_comment: revoc_comment,
                     key: this };
    var self = this;
    Signature.generate(sig_pars, function(err, newsig) {
      if (err) callback(err);
      else
        try {
          self._key.revsigs.push(newsig._sig);
          self.revsigs.push(newsig);
          self.updateStatus();
          callback(null);
        } catch(err) {
          logger.error(err);
          callback(err);
        }
    });
  } catch(err) { callback(err); }
}

// ### create_uid(options, [callback])
// 
// Revokes primary key
Key.prototype.generateUserId = function(name, expireseconds, callback) {
  try {
    var uid = this.addPacket({
      pkttype: PGP.PKT.USER_ID,
      name: name,
    });
    uid.generateSelfSig(expireseconds, function(err, newsig) {
      if (err) callback(err)
      else callback(null, uid);
    });
  } catch(err) { callback(err); }
}

// ### getEncryptionKey()
//
// Returns `Key` instance being the encryption key or subkey.
Key.prototype.getEncryptionKey = function() {
  for (var i=0,subkey=this.subkeys[i];i<this.subkeys.length;i++) 
    if (subkey.isEncryptionAlgo() && 
        subkey.selfsigs[0].hasEncryptionFlag() && 
        subkey.isValid()) 
      return subkey;

  for (var i=0,subkey=this.subkeys[i];i<this.subkeys.length;i++) 
    if (subkey.isEncryptionAlgo() && 
        subkey.isValid()) 
      return subkey;

  if (this.isEncryptionAlgo() && this.isValid()) 
    return this;

  throw new Error("No valid key nor subkey for encryption found");
}

// ### getFormatted()
//
// Returns serializable `object` with the formatted key properties.
Key.prototype.getFormatted = function() {
  var key = this.getFormattedPacket();
  key.revsigs = [];
  key.uids = [];
  key.subkeys = [];

  for (var i=0;i<this.revsigs.length;i++)
    key.revsigs.push(this.revsigs[i].getFormatted());
  for (var i=0;i<this.uids.length;i++)
    key.uids.push(this.uids[i].getFormatted());
  for (var i=0;i<this.subkeys.length;i++)
    key.subkeys.push(this.subkeys[i].getFormatted());

  return key;
}

// ### getKey(keyid)
//
// Return `key` instance as key or subkey with specified keyid
Key.prototype.getKey = function(keyid) {
  if (keyid == this.getKeyId())
    return this;
  else
    for (var i=0;i<this.subkeys.length;i++) {
      if (keyid == this.subkeys[i].getKeyId())
        return this.subkeys[i];
    }
  return null;
}

// ### getKeyId()
// 
// Returns primary key Id as `string`.
Key.prototype.getKeyId = function(keyid) {
  return this._key.pkt.keyid;
}

// ### getSubKeys()
// 
// Returns array of subkeys instances.
Key.prototype.getSubkeys = function() { 
  return this.subkeys; 
}

// ### getPacket()
//
// Returns primary key packet serializable object.
Key.prototype.getPacket = function() {
  return this._key.pkt;
}

// ### getUserIds()
// 
// Returns User Ids instances.
Key.prototype.getUserIds = function() { 
  return this.uids; 
}

Key.prototype.print = function() {
  console.log(JSON.stringify(this.getFormatted(), null, '\t'));
}

// ### Exports module methods
Key.prototype.updateStatus = function() {
  this.status.valid = false;
  this.status.revoked = false;
  for (var i=0; i<this.revsigs.length; i++) 
    if (this.revsigs[i].isValid()) {
      this.status.revoked = true;
    }
  var max_expiredate = 0;
  for (var i=0; i<this.uids.length; i++)  {
    this.uids[i].updateStatus();
    if (this.uids[i].isValid()) {
      var sig_expiredate = this.uids[i].getPacket().expiredate;
      if (sig_expiredate > max_expiredate) 
        max_expiredate = sig_expiredate;
      this.getPacket().expiredate = sig_expiredate;
      if (!this.status.revoked) this.status.valid = true;
    }
  }
  this.getPacket().expiredate = max_expiredate || this.getPacket().timestamp;
}

Key.prototype.verify = function(callback) {
  try {
    var calls = this.uids.concat(this.subkeys.concat(this.revsigs));
    var self = this;
    var n = 0;
    for (var i=0;i<calls.length;i++)  {
      calls[i].verify(function(err, valid) {
        n++; 
        if (err) self.logger.error(err);
        if (n == calls.length) {
          try {
            self.updateStatus();
            callback(null);
          } catch(err) { callback(err); }
        }
      });
    }
  } catch(err) { callback(err); }
}

exports.Key = Key;


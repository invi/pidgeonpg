const PGP = require("pgp/openpgpdefs");
const {Signature} = require('pgp/signature');
const {KeyTrait} = require('pgp/key-trait');
const {getStr} = require('util/lang');
const logger = require("util/logger");
const asymcrypto  = require('crypto/asym');

function Subkey() {
  var subkey = KeyTrait.create(Subkey.prototype);
  subkey._subkey = {
    pkt: null,
    selfsigs: [],
    revsigs: [],
    id: null,
    fp: null,
  }
  subkey.status = { 
    verified: false,
    valid: false,
    revoked: false,
  }
  subkey.selfsigs = [];
  subkey.revsigs = [];
  subkey.key = null;
  return subkey;
}

Subkey.load = function(_subkey, key, verified) {
  var subkey = new Subkey();
  subkey.key = key;
  subkey._subkey = _subkey;
  subkey._subkey.revsigs = _subkey.revsigs || [];
  subkey._subkey.selfsigs = _subkey.selfsigs || [];

  var _sigs = subkey._subkey.revsigs.concat(subkey._subkey.selfsigs);
  for (var i=0; i<_sigs.length; i++) {
    var sig = Signature.load(_sigs[i], key, verified);
    subkey.addSignature(sig, true);
  }

  subkey.hash_public_key();
  subkey.logger = logger.create("subkey.js");
  subkey.updateStatus();
  return subkey;
}

Subkey.prototype.addPacket = function(pkt) {
  if (pkt.pkttype == PGP.PKT.SIGNATURE) {
    var sig = Signature.load({pkt: pkt}, this.key);
    this.addSignature(sig);
    return sig;
  } else 
    throw new Error("Invalid subkey packet: " + pkt.pkttype);
}

Subkey.prototype.addSignature = function(newsig, ommitpacket) {
  var sigs, _sigs;
  switch(newsig._sig.pkt.sig_class) {
    case PGP.SIGCLASS.SUBKEY_SIG:
      sigs = this.selfsigs;
      _sigs = this._subkey.selfsigs;
      break;
    case PGP.SIGCLASS.SUBKEY_REV:
      sigs = this.revsigs;
      _sigs = this._subkey.revsigs;
      break;
    default:
      throw new Error("Invalid signature class: " + newsig._sig.pkt.sig_class);
    throw new Error("Invalid User Id signature class: " + pkt.sig_class);
  }
  var max = null;
  for (var i=sigs.length-1;i>=0;i--) 
    if (newsig._sig.pkt.timestamp > sigs[i]._sig.pkt.timestamp) 
      max = i;

  if (max!=null)  {
    sigs.splice(max, 0, newsig);
    if (ommitpacket != true) _sigs.splice(max, 0, newsig._sig);
  } else {
    sigs.push(newsig);
    if (ommitpacket != true) _sigs.push(newsig._sig);
  }
}

Subkey.prototype.generateRevocation = function(revoc_reason, revoc_comment, callback) {
  try {
    if (this.isRevoked()) throw new Error("The subkey is already revoked");
    var self = this;
    var pars = { 
      sig_class: PGP.SIGCLASS.SUBKEY_REV, 
      revoc_reason:  revoc_reason, 
      revoc_comment: revoc_comment,
      key: this.key,
      data: this.key.getDigest() + this.getDigest()
    }
    Signature.generate(pars, function(err, newsig) {
      try {
        if (err) callback(err);
        else {
          self.addSignature(newsig);
          self.updateStatus();
          self.key.updateStatus();
          callback(null);
        } 
      } catch(err) { callback(err) }
    });
  } catch(err) { callback(err) }
}

Subkey.prototype.generateSelfSig = function(expireseconds, callback) {
  try {
    var self = this;
    var ts = Math.floor(Date.now() / 1000); 
    var sig_pars = {
      sig_class: PGP.SIGCLASS.SUBKEY_SIG,
      key: this.key,
      timestamp: ts,
      expiredate: ts + expireseconds, 
      data: this.key.getDigest() + this.getDigest(),
    }
    var self = this;
    Signature.generate(sig_pars, function(err, newsig) {
      try {
        if (err) callback(err)
        else {
          self.addSignature(newsig);
          self.updateStatus();
          self.key.updateStatus();
          callback(null);
        }
      } catch(err) { callback(err) };

    });
  } catch(err) { callback(err); }
}

Subkey.prototype.getFormatted = function() {
  var subkey = this.getFormattedPacket();
  subkey.revsigs = [];
  subkey.selfsigs = [];
  for (var i=0;i<this.revsigs.length;i++)
    subkey.revsigs.push(this.revsigs[i].getFormattedPacket());
  for (var i=0;i<this.selfsigs.length;i++)
    subkey.selfsigs.push(this.selfsigs[i].getFormattedPacket());
  return subkey;
}

Subkey.prototype.getKeyId = function(keyid) {
  return this._subkey.pkt.keyid;
}

Subkey.prototype.getPacket = function() {
  return this._subkey.pkt;
}

Subkey.prototype.getSelfSig = function() {
  return this.selfsigs[0];
}

Subkey.prototype.updateStatus = function() {
  this.status.valid = false;
  this.status.revoked = false;
  for (var i=0; i<this.revsigs.length; i++) {
    if (this.revsigs[i].isValid()) {
      this.status.revoked = true;
    }
  }
  var max_expiredate = 0;
  for (var i=0; i<this.selfsigs.length; i++) 
    if (this.selfsigs[i].isValid())  {
      var sig_expiredate = this.selfsigs[i].getPacket().expiredate;
      if (sig_expiredate > max_expiredate) 
        max_expiredate = sig_expiredate;
      this.getPacket().expiredate = sig_expiredate;
      if (!this.status.revoked) this.status.valid = true;
    }
  this.getPacket().expiredate = max_expiredate;
}

Subkey.prototype.verify = function(callback) {
  try {
    var self = this;
    var sigs = this.revsigs.concat(this.selfsigs);
    var digest = this.key.getDigest() + this.getDigest();
    var n = 0;
    if (sigs.length == 0) callback(null);
    for (var i=0; i<sigs.length; i++)  {
      sigs[i].verifyData(digest, function(err, valid) {
        try {
          n++; 
          if (err) self.logger.error(err);
          if (n == sigs.length) {
            self.updateStatus();
            callback(null);
          }
        } catch(err) { callback(err); }
      });
    }
  } catch(err) { callback(err); }
}

exports.Subkey = Subkey;

const PGP = require("pgp/openpgpdefs");
const misc = require('util/misc');
const {Signature} = require('pgp/signature');
const {BaseTrait} = require('pgp/base-trait');
const {getStr} = require('util/lang');
const logger = require('util/logger');

function UserId() {
  var uid = BaseTrait.create(UserId.prototype);
  uid._uid = { 
    pkt: null,
    sigs: [],
    selfsigs: [],
    revsigs: [],
  }
  uid.status = {
    verified: false,
    valid: false,
    revoked: false,
  }
  uid.sigs = [ ];
  uid.selfsigs = [ ];
  uid.revsigs = [ ];
  uid.key = null;
  uid.logger = null;
  return uid;
}

UserId.load = function(_uid, key, verified) {
  var uid = new UserId();
  uid.key = key;
  uid._uid = _uid;
  uid._uid.revsigs = _uid.revsigs || [];
  uid._uid.selfsigs = _uid.selfsigs || [];
  uid._uid.sigs = _uid.sigs || [];

  var _sigs = uid._uid.revsigs.concat(uid._uid.selfsigs, uid._uid.sigs);
  for (var i=0; i<_sigs.length; i++) {
    var sig = Signature.load(_sigs[i], key, verified);
    uid.addSignature(sig, true);
  }

  uid.logger = logger.create("userid.js");
  uid.updateStatus();
  return uid;
}

UserId.prototype.addPacket = function(pkt) {
  if (pkt.pkttype == PGP.PKT.SIGNATURE) {
    var sig = Signature.load({pkt: pkt}, this.key);
    this.addSignature(sig);
  } else 
    throw new Error("Invalid User Id packet type: " + pkt.pkttype);
  return sig;
}

UserId.prototype.addSignature = function(newsig, omitpacket) {
  var sigs, _sigs;
  if (newsig.isUserIdSig() && newsig.isSelf()) {
    sigs = this.selfsigs;
    _sigs = this._uid.selfsigs;
  } else if (newsig.isUserIdSig()) {
    sigs = this.sigs;
    _sigs = this._uid.sigs;
    newsig.issuerkeyid = newsig._sig.pkt.keyid;
  } else if (newsig.isUserIdRev()) {
    sigs = this.revsigs;
    _sigs = this._uid.revsigs;
  } else {
    throw new Error("Invalid User Id signature class: " + newsig._sig.pkt.sig_class);
  }
  var max = null;
  for (var i=sigs.length-1;i>=0;i--) 
    if (newsig._sig.pkt.timestamp > sigs[i]._sig.pkt.timestamp) 
      max = i;

  if (max!=null)  {
    sigs.splice(max, 0, newsig);
    if (omitpacket != true) _sigs.splice(max, 0, newsig._sig);
  } else {
    sigs.push(newsig);
    if (omitpacket != true) _sigs.push(newsig._sig);
  }
}

UserId.prototype.generateRevocation = function(revoc_reason, revoc_comment, callback) {
  try {
    if (this.isRevoked()) throw new Error("The User Id is already revoked");
    var self = this;
    var sig_pars = { sig_class: PGP.SIGCLASS.UID_REV, 
                     revoc_reason: revoc_reason, 
                     revoc_comment: revoc_comment,
                     key: this.key,
                     data: this.key.getDigest() + this.getDigest() };
    Signature.generate(sig_pars, function(err, newsig) { 
      try {
        if (err) callback(err) 
        else {
          self.addSignature(newsig);
          self.updateStatus();
          self.key.updateStatus();
          callback(null);
        }
      } catch(err) { callback(err); }
    });
  } catch(err) { callback(err); }
}

UserId.prototype.generateSelfSig = function(expireseconds, callback) {
  var self = this;
  var ts = Math.floor(Date.now() / 1000); 
  var sig_pars = { sig_class: PGP.SIGCLASS.KEY_SIG,
                   key: this.key,
                   timestamp: ts,
                   expiredate: ts + expireseconds, 
                   data: this.key.getDigest() + this.getDigest() };

  Signature.generate(sig_pars, function(err, newsig) { 
    try {
      if (err) callback(err)
      else {
        self.addSignature(newsig);
        self.updateStatus();
        self.key.updateStatus();
        callback(null);
      }
    } catch(err) { callback(err); }
  });
}

/**
 * Gives the digest corresponding to a User Id packet
 * @function 
 * @param uid User Id packet
 * @param sig Self Signature packet
 */
UserId.prototype.getDigest = function(sig_version) {
  var uidlen = this.getName().length;
  var md = "";

  //if(uid.attrib_data) 
  //{
  //  //XXX not used
  //  if(sig_version >= 4) 
  //  {
  //    md = String.fromCharCode(0xd1) +  /* packet of type 17 */
  //         misc.u32_to_string(uidlen);
  //  }
  //  md = md.concat(uid);
  //}
  //else 
  md += String.fromCharCode(0xb4) +		/* indicates a userid packet */
          misc.u32_to_string(uidlen);   /* always use 4 length bytes */
  md += this.getName();
  return md;
}

UserId.prototype.getFormatted = function() {
  var ret = this.getFormattedPacket();
  ret.sigs = [];
  ret.selfsigs = [];
  ret.revsigs = [];
  for (var i=0;i<this.revsigs.length;i++)
    ret.revsigs.push(this.revsigs[i].getFormattedPacket());
  for (var i=0;i<this.selfsigs.length;i++)
    ret.selfsigs.push(this.selfsigs[i].getFormattedPacket());
  for (var i=0;i<this.sigs.length;i++)
    ret.sigs.push(this.sigs[i].getFormattedPacket());
  return ret;
}

UserId.prototype.getFormattedPacket = function() {
  return {name : this.getName(),
          expired : this.isExpired(),
          revoked: this.status.revoked,
          valid : this.status.valid,
          verified: this.status.verified,
          isImage : this.isImage(),
          image : this.getImage(),
          ringstatus: this.status.ringstatus}
}
UserId.prototype.getImage = function() {
  var ret = "";
  if (this.isImage())
    ret += this._uid.pkt.attribs[0].image;
  return ret;
}

UserId.prototype.getName = function() {
  return this._uid.pkt.name;
}

UserId.prototype.getPacket = function() {
  return this._uid.pkt;
}

UserId.prototype.getPacketType = function() {
  return this._uid.pkt.pkttype;
}

UserId.prototype.getSelfSig = function() {
  return this.selfsigs[0];
}


UserId.prototype.isExpired = function() {
  if (!this.status.verified) 
    this.updateStatus();

  return this.status.expired;
}

UserId.prototype.isImage = function() {
  return this._uid.pkt.numattribs && this._uid.pkt.attribs[0].type == 1;
}



UserId.prototype.isSignedBy = function(key) {
  for (var i=0;i<this.sigs.length;i++)
    if (this.sigs[i].getKeyId() == key.getKeyId())
      return true
  return false;
}

UserId.prototype.signUserId = function(key, callback) {
  try {
    var self = this;
    var sig_pars = { sig_class: PGP.SIGCLASS.UID_SIG, 
                     key: key,
                     holdingkey: this.key,
                     keyid: key.getKeyId(),
                     data: this.key.getDigest() + this.getDigest() };

    Signature.generate(sig_pars, function(err, newsig) { 
      try {
        if (err) callback(err)
        else {
          self.addSignature(newsig);
          self.updateStatus();
          self.key.updateStatus();
          callback(null);
        }
      } catch(err) {
        callback(err);
      }
    });
  } catch(err) {
    callback(err);
  }
}


UserId.prototype.updateStatus = function() {
  this.status.valid = false;
  this.status.revoked = false;
  for (var i=0; i<this.revsigs.length; i++) 
    if (this.revsigs[i].isValid()) {
      this.status.revoked = true;
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

UserId.prototype.verify = function(callback) {
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

exports.UserId = UserId;

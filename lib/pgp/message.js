// # message 
// 
// <!--name=ppgapp-->
// 
// This modules encrypts a message for several recipiens and signing with a given key.

const PGP = require("pgp/openpgpdefs");
const misc = require('util/misc');
const logger = require("util/logger").create("message.js");
const IOBuf = require('util/iobuf').IOBuf;
const armor = require('encode/armor');
const Signature = require('pgp/signature').Signature;
const asymcrypto = require('crypto/asym');
const symcrypto = require('crypto/sym');
const {storage} = require('ring/storage');
const builder = require('pgp/builder');

function EncryptedMessage(data, pub_keys, sig_keys) {
  this.pub_keys = pub_keys || [];
  this.sig_keys = sig_keys || [];
  this.data = data;
  this.encryption_cipher = 9;
  this.sessionkey_packets = "";
  this.datatoencrypt = "";
  this.sess_key = null;
}

EncryptedMessage.prototype.encrypt = function(callback) {
  var self = this;
  //XXX find intersection of preferred symciphers
  try {
    symcrypto.generateSessionKey(this.encryption_cipher, function(sess_key) {
      try { 
        self.sess_key = sess_key;
        var ncount = 0;
        for (var i=0;i<self.pub_keys.length;i++) {
          var pubkey = self.pub_keys[i];
          builder.write_pubkey_encryptedsessionkey_packet(self.encryption_cipher, sess_key, pubkey, 
                                                            function(err, sessionkey_packet) {
            if (err) { callback(err); return; }
            self.sessionkey_packets += sessionkey_packet;
            ncount++;
            if (ncount == self.pub_keys.length) {
              self.sign_data(function(err) {
                if (err) { callback(err); return; };
                self.encrypt_data(function(err) {
                  if (err) { callback(err); return; };
                  var aResult = armor.encode(self.sessionkey_packets + self.encrypted_data, PGP.ARMOR.MESSAGE);
                  callback(null, aResult);
                });
              });
            }
          });
        }
      } catch(err) {
        callback(err);
      }
    }); 
  } catch(err) {
    callback(err);
  }
}

EncryptedMessage.prototype.sign_data = function(callback) {
  try {
    var self = this;
    if (this.sig_keys.length > 1) {
      callback(new Error("Nested signatures not implemented"));
    } else if(this.sig_keys.length) {
      var sig_pars = {
                      pkttype: PGP.PKT.SIGNATURE,
                      version: 3,
                      sig_class: PGP.SIGCLASS.BINARY, 
                      pubkey_algo: this.sig_keys[0].getAlgo(),
                      digest_algo: PGP.HASH.SHA1,
                      key: this.sig_keys[0],
                      data: this.data, 
                     }

      Signature.generate(sig_pars, function(err, sig) {
        try {
          if (err) { callback(err); }
          else {
            self.datatoencrypt += builder.write_onepasssignature_packet(sig);
            self.datatoencrypt += builder.write_literal_packet(self.data);
            self.datatoencrypt += sig.write_packet();
            callback(null);
          }
        } catch(err) { callback(err); }
      });
    } else {
      this.datatoencrypt += builder.write_literal_packet(this.data);
      callback(null);
    }
  } catch(err) { callback(err); }
}

EncryptedMessage.prototype.encrypt_data = function(callback) {
  try {
    var self = this;
    builder.write_encryptedintegrityprotecteddata_packet(this.encryption_cipher,
      this.sess_key, this.datatoencrypt, function(err, encrypted_packet) {
        if (err) { callback(err); return };
        self.encrypted_data = encrypted_packet;
        callback(null);
    });
  } catch(err) {
    callback(err);
  }
}

function Message(text) {
  this.text = text;
  this.enc_keys = [];
  this.enc_keyids = [];
  this.sig_keys = [];
  this.sig_keyids = [];
}

Message.prototype.getKeyIds = function() {
  return this.keyids;
}

Message.prototype.encrypt = function(ekeyids, skeyids, callback) {

  this.enc_keyids = ekeyids;
  for (var i=0; i<ekeyids.length; i++) {
    var enc_key = storage.find(ekeyids[i]);
    this.enc_keys.push(enc_key);
  }
  if (skeyids && skeyids.length) {
    this.sig_keyids = skeyids;
    for (var i=0; i<skeyids.length; i++) {
      var sig_key = storage.fetchKey(skeyids[i]);
      this.sig_keys.push(sig_key);
    }
  }
  var em = new EncryptedMessage(this.text, this.enc_keys, this.sig_keys);
  em.encrypt(callback);
}

Message.prototype.sign = function(keyid, callback)
{
  this.keyid = keyid;
  this.key = storage.find(keyid);

  var prep = PGP.ARMOR.SIGNEDMESSAGE.BEGIN + 
             "\nHash: SHA1\n\n" + this.text + "\n";

  var pars = { 
    sig_class: PGP.SIGCLASS.CANONICAL,
    issuer_key: this.key,
    key: this.key,
    data: this.text,
  }
  Signature.generate(pars, function(err, newsig) {
    if (err) callback(err)
    else {
     var sigblock = armor.encode(newsig.write_packet(), PGP.ARMOR.SIGNATURE);
     callback(null, prep+sigblock);
    }
  });
}

exports.Message = Message;

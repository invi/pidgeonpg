const PGP = require("pgp/openpgpdefs");
const logger = require("util/logger").create('encryptedmessage.js');
const misc = require('util/misc');
const {Parser} = require('pgp/parser');
const {IOBuf} = require('util/iobuf');
const armor = require('encode/armor');
const zlib = require('compression/zlib');
const bzip2 = require('compression/bzip2-str');
const {Signature} = require('pgp/signature');
const symcrypto = require('crypto/sym');
const {storage} = require('ring/storage');

function sessdata_checksum(sessdata) {
   var checksumVal = (sessdata.charCodeAt(sessdata.length-2) << 8) + 
                      sessdata.charCodeAt(sessdata.length-1);
   
   var checksumCalc=0;
   for (var i=0;i<sessdata.length-2;i++)
     checksumCalc += sessdata.charCodeAt(i);

   return (checksumCalc == checksumVal);
}

function uncompress(compressed_pkt) {
  var data;
  switch(compressed_pkt.algorithm) {
    case PGP.COMPRESS_ALGO.UNCOMPRESSED:
      data = compressed_pkt.buf;
      break;
    case PGP.COMPRESS_ALGO.ZIP:
      data = zlib.inflate(compressed_pkt.buf);
      break;
    case PGP.COMPRESS_ALGO.ZLIB:
      data = zlib.uncompress(compressed_pkt.buf);
      break;
    case PGP.COMPRESS_ALGO.BZIP2:
      data = bzip2.decode(compressed_pkt.buf);
      break;
    default:
      throw Error("Unknown compression algo: " + compressed_pkt.algorithm);
  }
  return new IOBuf(data);
}

function parse_decrypted_packets(inp) {
  var packets = { };
  while(Parser.parse(inp, pkt = {}, logger) != -1) {
    switch(pkt.pkttype) {
      case PGP.PKT.PLAINTEXT:
      packets.pt = pkt;
      break;
      //XXX Nested order, by now assume only one
      case PGP.PKT.ONEPASS_SIG:
      packets.onesig = pkt;
      break;
      case PGP.PKT.SIGNATURE:
      packets.sig = pkt;
      break;
      case PGP.PKT.MDC:
      packets.mdc = pkt;
      break;
      case PGP.PKT.COMPRESSED:
      packets.compressed = pkt;
      inp = uncompress(pkt);
      break;
      default:
      throw Error("Invalid decrypted packet type: " + pkt.pkttype);
    }
  }
  return packets;
}

function EncryptedMessage(inp) {
  this.inp = inp;
  this.pubkeyenc = [];
  this.encdata = null;
  this.key = null;
  this.validChecksum = false;
}

EncryptedMessage.prototype.getEncryptedSessionKey = function(n) {
  return this.pubkeyenc[n].data;
}

EncryptedMessage.prototype.decrypt = function(callback) {
  var found = false;
  var i = 0;
  for (;i<this.pubkeyenc.length;i++)
    if ((this.key = storage.find(this.getKeyId(i)))!=false) {
      found = true;
      break;
    }

  if (!found) throw new Error("Decryption key not found");

  var self = this;
  var decryption_key = this.key.getKey(this.getKeyId(i));
  if (decryption_key) 
    decryption_key.decrypt(this.getEncryptedSessionKey(i), function(sessdata) {
      try {
        self.validChecksum = sessdata_checksum(sessdata);
        var algo = sessdata.charCodeAt(0);
        var sesskey = sessdata.substr(1, sessdata.length-3);
        var data = misc.atos(self.encdata.data);

        var decrypted_data = 
          symcrypto.decrypt(algo, sesskey, data, false);

        var inp = new IOBuf(decrypted_data);
        var packets = parse_decrypted_packets(inp);
        if (packets.sig) {
          try {
            var key = storage.fetchKey(packets.onesig.keyid);
            var text = packets.pt.buf;
            var sig = Signature.load({pkt:packets.sig}, key);
            sig.verifyData(text, function(err, isValid) {
              if (err) logger.error(err);
              callback(err, {msg: packets.pt.buf, type: isValid ? PGP.DECRYPT_RC.SIGN_VERIFIED: PGP.DECRYPT_RC.SIGN_NOT_VALID, sign_keyid: key.getKeyIdStr(i) });
            });
          } catch (err) {
            logger.error(err);
            callback(err, {msg: packets.pt.buf, type: PGP.DECRYPT_RC.SIGN_UNKNOW_KEY, sign_keyid:""});
          }
        } 
        else {
          callback(null, {msg: packets.pt.buf, type: PGP.DECRYPT_RC.NOT_SIGNED, sign_keyid:"" });
        }

      } catch(err) {
        logger.error(err);
        callback(err);
      }
    });
}

EncryptedMessage.prototype.getKeyId = function(n) {
  return this.pubkeyenc[n].keyid;
}

EncryptedMessage.prototype.getKeyIdStr = function(n) {
  //XXX Check zeros
  return this.pubkeyenc[n].keyid.toString(16).toUpperCase(); 
}


EncryptedMessage.create = function(msgdata) {
  var msgbindata = armor.decode(msgdata, [ PGP.ARMOR.MESSAGE ]);
  var inp = new IOBuf(msgbindata);
  var emsg =  new EncryptedMessage(inp);
  emsg.parse();
  return emsg;
}

EncryptedMessage.prototype.parse = function() {
  var pkt = { },
      rc = 0;

  while ((rc = Parser.parse(this.inp, pkt.pkt = {}, logger)) != -1 ) {
    if ( rc ) {
      throw Error("Error reading PGP message packet");
    }
    switch(pkt.pkt.pkttype) {
      case PGP.PKT.PUBKEY_ENC:
      this.pubkeyenc.push(pkt.pkt);
      break;
      case PGP.PKT.ENCRYPTED:
      case PGP.PKT.ENCRYPTED_MDC:
      this.encdata = pkt.pkt;
      break;
      default:
        throw Error("Invalid PGP message packet type: " + pkt.pkt.pkttype);
    }
  }
}

exports.EncryptedMessage = EncryptedMessage;


const PGP = require("pgp/openpgpdefs");
const logger = require("util/logger").create("clearsignmessage.js");
const misc = require('util/misc');
const {Parser} = require('pgp/parser');
const {IOBuf} = require('util/iobuf');
const armor = require('encode/armor');
const {Signature} = require('pgp/signature');
const {storage} = require('ring/storage');


function ClearSignMessage(text, inp) {
  this.text = text;
  this.inp = inp
  this.sig = null;
  this._sig = null;
  this.key = null;
}

ClearSignMessage.create = function(msgdata) {
  var dec_armor= armor.decode_cleartextsign(msgdata);
  var inp = new IOBuf(dec_armor.bin_block);
  var smsg = new ClearSignMessage(dec_armor.text_block, inp);
  smsg.parse();
  return smsg;
}

ClearSignMessage.prototype.verify = function(callback) {
  try {
    var self = this;
    var issuerkey = storage.fetchKey(this.getIssuerKeyIdStr())
    this.sig = Signature.load({pkt: this._sig}, issuerkey);
    var tohash = this.text.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n");
    tohash = tohash.substring(0, tohash.length-2);
    this.sig.verifyData(tohash, function(err, valid) {
      if (err) callback(err) 
      else { callback(null, valid); }
    });
  } catch(err) { callback(err); }
}

ClearSignMessage.prototype.getKeyId = function()
{
  return this._sig.keyid;
}

ClearSignMessage.prototype.getIssuerKeyIdStr = function() { 
  return misc.stohex(this.getKeyId()).toUpperCase() 
}

ClearSignMessage.prototype.fetchKey = function()
{
  this.key = storage.find(this.getKeyId());
  if (!this.key) throw "PGP.ERR.NOT_FOUND";
}

ClearSignMessage.prototype.parse = function() 
{
  var pkt = { },
      rc = 0;

  while ((rc = Parser.parse(this.inp, pkt = {})) != -1 )
  {
    if ( rc )
    {
      logger.error("readblock error");
      return -1;
    }
    switch(pkt.pkttype) 
    {
      case PGP.PKT.SIGNATURE:
      this._sig = pkt;
      break;
      default:
        logger.error("Wrong packet type (%d)", pkt.pkttype);
    }
  }
  return 0;
}

exports.ClearSignMessage = ClearSignMessage; 

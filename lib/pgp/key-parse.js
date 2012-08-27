const PGP = require("pgp/openpgpdefs");
const misc = require('util/misc');
const armor = require('encode/armor');
const {Key} = require("pgp/key");
const {IOBuf} = require('util/iobuf');
const {Parser} = require('pgp/parser');
const {data} = require('self');
const file = require('file');
const url = require("url");
const logger = require("util/logger").create("key-parse");

function parsekeys(block, isBin) {
  var bin_block = null;
  if (isBin)  
    bin_block = block; 
  else
    bin_block = armor.decode(block, [PGP.ARMOR.PUBLICKEY,PGP.ARMOR.PRIVATEKEY]);

  var inp = new IOBuf(bin_block);
  var keylist = [];
  var key = null;
  var rc = null;
  var pkt = null;

  while((rc=Parser.parse(inp, pkt={})) != -1) {
    if (rc) return rc;
    else {
      switch(pkt.pkttype) {
        case PGP.PKT.PUBLIC_KEY:
        case PGP.PKT.SECRET_KEY:
          key = Key.loadFromPacket(pkt, logger);
          keylist.push(key);
          break;
        default:
          if (key) key.addPacket(pkt);
          break;
      }
    }
  }
  return keylist;
}

function parsekeysfile(fname) {
  var block = data.load(fname);
  var bin_block = armor.decode(block, [PGP.ARMOR.PUBLICKEY, PGP.ARMOR.PRIVATEKEY]);
  if (!bin_block) {
    var fn = url.toFilename(data.url(fname));
    bin_block = file.read(fn, "b");
  }
  return parsekeys(bin_block, true);
}

exports.parsekeys = parsekeys;
exports.parsekeysfile = parsekeysfile;

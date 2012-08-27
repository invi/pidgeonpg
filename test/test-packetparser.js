const PGP = require("pgp/openpgpdefs");
const misc = require('util/misc');
const {IOBuf} = require('util/iobuf');
const {Parser} = require('pgp/parser');
const armor = require('encode/armor');
const {data} = require('self');

exports.testPacketParse = function(test)
{
  var filedata = data.load("test/key1.asc");
  var bin_block = armor.decode(filedata, [PGP.ARMOR.PUBLICKEY, PGP.ARMOR.PRIVATEKEY]);

  var inp = new IOBuf(bin_block);

  var rc,
      pkt;

  while( (rc=Parser.parse(inp, pkt = { })) != -1 ) 
  {
    if (pkt.pkttype == PGP.PKT.SECRET_KEY)
    {
      test.assertEqual(pkt.version, 4, "pkt.version");
      test.assertEqual(pkt.pubkey_algo, 1, "pkt.pubkey_algo");
    }
  }
}

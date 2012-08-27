const PGP = require("pgp/openpgpdefs");
const logger = require("util/logger").create("armor.js");
const base64Decode = require("api-utils/base64").decode;
const base64Encode = require("api-utils/base64").encode;
const misc = require('util/misc');

/**
 * Internal function to calculate a CRC-24 checksum over a given string (data)
 * @param data [String] data to create a CRC-24 checksum for
 * @return [Integer] the CRC-24 checksum as number
 */
function createcrc24 (data) {
  var crc = 0xB704CE;
  var i;
  var mypos = 0;
  var len = data.length;
  while (len--) {
    crc ^= (data[mypos++].charCodeAt()) << 16;
    for (i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000)
              crc ^= 0x1864CFB;
        }
    }
    return crc & 0xFFFFFF;
}

function decode_cleartextsign(ablock)
{
  //trim white spaces
  var bin_block = "",
      text_block = "";

  ablock = ablock.replace(/^\s+|\s+$/g,"");
  if ( (ablock.indexOf(PGP.ARMOR.SIGNEDMESSAGE.BEGIN) == 0) &&
       (ablock.indexOf(PGP.ARMOR.SIGNATURE.BEGIN) <
        ablock.indexOf(PGP.ARMOR.SIGNATURE.END)) ) 
  {
    ablock = ablock.substr(PGP.ARMOR.SIGNEDMESSAGE.BEGIN.length);

    var text_ini = ablock.indexOf("\n\n") + 2;
    var text_end = ablock.indexOf(PGP.ARMOR.SIGNATURE.BEGIN);
    var text_block  = ablock.substr(text_ini, text_end - text_ini);

    var bin_ini = ablock.indexOf(PGP.ARMOR.SIGNATURE.BEGIN);
    ablock = ablock.substr(bin_ini);

    var bin_block = decode_armor(ablock, [PGP.ARMOR.SIGNATURE]);

    //XXX missing checksum
    return { text_block: text_block, bin_block: bin_block };
  }
  else {
    return false;
  }
}

function decode_armor(ablock, tests) {

  //trim white spaces
  ablock = ablock.replace(/^\s+|\s+$/g,"");
  var ret_block = "";
  for (var i in tests) 
  {
    var test = tests[i];

    var idxbegin, idxend;
    while(((idxbegin = ablock.indexOf(test.BEGIN)) >= 0) && ((idxend = ablock.indexOf(test.END))) > 0) 
    {
      var bin_block = "";
      var blockidxend = idxend + test.END.length;
      idxbegin += test.BEGIN.length;
      idxend = idxend - test.BEGIN.length - 1;
      var currblock = ablock.substr(idxbegin, idxend);

      ablock = ablock.substr(blockidxend);
      ablock = ablock.replace(/^\s+|\s+$/g,"");

      var fst = currblock.indexOf("\n\n");
      currblock = currblock.substr(fst + 2);
      
      var j;
      while((j = currblock.indexOf("\n")) > 0 )
      {
        bin_block += base64Decode(currblock.substr(0, j));
        currblock = currblock.substr(j + 1);
      }

      var crc = createcrc24(bin_block) 
      var crcdata = base64Decode(currblock.substr(1))
      var crcdataint = misc.string_to_u24(crcdata);

      if (crc != crcdataint)
      {
        throw new Error("PGP.ERR.BAD_CHECKSUM");
      }
      else
        ret_block += bin_block;
    }
  }
  return ret_block;
}

function encode_armor(data, _enctype) 
{
  var enctype = _enctype || PGP.ARMOR.PUBLICKEY;
  var enckey = base64Encode(data);
  var ret = enctype.BEGIN + "\n\n";
  for (var i=0; i < enckey.length; i+=64)
  {
    ret += enckey.substr(i, 64) + "\n";
  }

  var c = createcrc24(data);
  var crc = String.fromCharCode(c >> 16) +
            String.fromCharCode((c >> 8) & 0xFF) +
            String.fromCharCode(c & 0xFF);

  ret += "=" + base64Encode(crc) + "\n";
  ret += enctype.END;
  return ret;
}

exports.encode = encode_armor;
exports.decode = decode_armor;
exports.decode_cleartextsign = decode_cleartextsign;




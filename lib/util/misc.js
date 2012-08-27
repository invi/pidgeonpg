const PGP = require('pgp/openpgpdefs');
const IOBuf = require('util/iobuf').IOBuf;
//const logger = require("util/logger").create("misc.js");

	/**
	 * convert a string to an array of integers(0.255)
	 * @param [String] string to convert
	 * @return [Array [Integer 0..255]] array of (binary) integers
	 */
	exports.str2bin = function(str) {
		var result = new Array();
		for (var i = 0; i < str.length; i++) {
			result[i] = str.charCodeAt(i);
		}
		
		return result;
	};

	/**
	 * convert an array of integers(0.255) to a string 
	 * @param [Array [Integer 0..255]] array of (binary) integers to convert
	 * @return [String] string representation of the array
	 */
	exports.bin2str = function(bin) {
		var result = "";
		for (var i = 0; i < bin.length; i++) {
			result += String.fromCharCode(bin[i]);
		}
		return result;
	};

/**
 * calculates a 16bit sum of a string by adding each character codes modulus 65535
 * @param text [String] string to create a sum of
 * @return [Integer] an integer containing the sum of all character codes % 65535
 */
exports.calc_checksum = function(text) {
	var checksum = {  s: 0, add: function (sadd) { this.s = (this.s + sadd) % 65536; }};
	for (var i = 0; i < text.length; i++) {
		checksum.add(text.charCodeAt(i));
	}
	return checksum.s;
};

function write_packet_header(pkttype, pktlen) {
  var ret = "",
      ctb = 0x80 | (pkttype << 2),
      n;

  if (pktlen > 0xffff) { //XXX 32bit
    ctb |= 0x2;
    n = 4;
  } else if(pktlen > 0xff) {
    ctb |= 0x1;
    n = 2;
  } else {
    ctb |= 0x0;
    n = 1;
  } 

  ret += String.fromCharCode(ctb);
  while(n--)
    ret += String.fromCharCode((pktlen >> (n*8)) & 0xff);

  return ret;
}

function string_to_u32(buffer)
{
  var a;
  a =  (buffer[0] << 24);
  a |= buffer[1] << 16;
  a |= buffer[2] << 8;
  a |= buffer[3];
  return a >>> 0;
}

function string_to_u24(buffer) {
  var a;
  a = buffer.charCodeAt(0) << 16;
  a |= buffer.charCodeAt(1) << 8;
  a |= buffer.charCodeAt(2);
  return a >>> 0;
}

function u32_to_string(uint) {
  var ret = "";
  ret += String.fromCharCode(((uint >> 24)) & 0xff);
  ret += String.fromCharCode((uint >> 16) & 0xff);
  ret += String.fromCharCode((uint >> 8) & 0xff);
  ret += String.fromCharCode(uint & 0xff);
  return ret;
}

function u32_to_array(uint) {
  var ret = [ ];
  ret.push(((uint >> 24) >>> 0) & 0xff);
  ret.push((uint >> 16) & 0xff);
  ret.push((uint >> 8) & 0xff);
  ret.push(uint & 0xff);
  return ret;
}

function u16_to_string(uint) {
  var ret = "";
  ret += String.fromCharCode((uint >> 8) & 0xff);
  ret += String.fromCharCode(uint & 0xff);
  return ret;
}

/**
 * Converts bytearray to binary string
 * @function 
 * @param arr byte array 
 */
function atos(arr) {
  var d = "";
  try {
    for (var i = 0; i<arr.length; i++)
      d += String.fromCharCode(arr[i]);
  } catch(e) {
    logger.error(e);
  } 
  return d;
}

function atohex(arr) {
  var d = "";
  for (var i = 0; i<arr.length; i++)
    if (arr[i])
      d += ("0" + arr[i].toString(16)).slice(-2);
    else
      continue;
  return d;
}

function stoa(str) {
  var ret = [];
  try {
    for (var i in str)
      ret.push(str.charCodeAt(i));
  } catch(e) {
    logger.error(e);
  } 
  return ret;
}

function stohex(rawHash) {
  var hash = "";
  try {
    function toHexString(charCode) {
        return ("0" + charCode.toString(16)).slice(-2);
    }
    hash = [toHexString(rawHash.charCodeAt(i)) for (i in rawHash)].join("");
  } catch(e) {
    logger.error(e);
  }
  return hash;
}

function hextoa(val) {
  var ret = [];
  var i=0
  if (val.length % 2) {
    ret.push(parseInt(val.substr(0,1),16));
    i++;
  }
  for (; i< val.length; i+=2)
    ret.push(parseInt(val.substr(i,2),16));
  return ret;
}

/* Temporary helper. */
function pubkey_get_nsig (algo) {
  var n = 0;
  /* ECC is special.  */
  switch (algo) {
  case PGP.PUBKEY.ALGO.RSA:
    return 1;
  case PGP.PUBKEY.ALGO.ELGAMAL_E:
  case PGP.PUBKEY.ALGO.DSA:
    return 2;
  default:
    return 0;
  }
}

/* Return the number of public key parameters as used by OpenPGP.  */
function pubkey_get_npkey(algo) {
  /* ECC is special.  */
  switch(algo) {
    case PGP.PUBKEY.ALGO.RSA:
      return 2;
    case PGP.PUBKEY.ALGO.ELGAMAL_E:
      return 3;
    case PGP.PUBKEY.ALGO.DSA:
      return 4;
    default:
      return 0;
  }
}

/* Return the number of secret key parameters as used by OpenPGP.  */
function pubkey_get_nskey(algo) {
  switch (algo) {
    case PGP.PUBKEY.ALGO.RSA:
      return 6;
    case PGP.PUBKEY.ALGO.DSA:
      return 5;
    case PGP.PUBKEY.ALGO.ELGAMAL_E:
      return 4;
    default:
      return 0;
  }
}

function pubkey_get_nenc(algo) {
  switch (algo) {
    case PGP.PUBKEY.ALGO.RSA:
      return 1;
    case PGP.PUBKEY.ALGO.ELGAMAL_E:
      return 2;
  }
  return 0;
}

function pk_test_algo(algo) {
  switch (algo) {
    case PGP.PUBKEY.ALGO.RSA:
      return 0;
    case RSA_E: 
    case RSA_S: 
    case ELGAMAL_E: 
    case DSA: 
    case ECDH: 
    case ECDSA:
    case ELGAMAL:
      return PGP.ERR.PUBKEY_ALGO_NI;
    default:
      return PGP.ERR.PUBKEY_ALGO;
  }
}

function md_test_algo(algo) {
  switch (algo) {
    case PGP.HASH.SHA1:
      return 0;
    case PGP.HASH.MD5:
    case PGP.HASH.RIPEMD160:
    case PGP.HASH.SHA256:
    case PGP.HASH.SHA384:
    case PGP.HASH.SHA512:
    case PGP.HASH.SHA224:
      return PGP.ERR.DIGEST_ALGO_NI;
    default:
      return PGP.ERR.DIGEST_ALGO;
  }
}



/* Return the block length of an OpenPGP cipher algorithm.  */
function openpgp_cipher_blocklen (algo) {
  /* We use the numbers from OpenPGP to be sure that we get the right
     block length.  This is so that the packet parsing code works even
     for unknown algorithms (for which we assume 8 due to tradition).

     NOTE: If you change the the returned blocklen above 16, check
     the callers because they may use a fixed size buffer of that
     size. */
  switch (algo) {
    case 7: case 8: case 9: /* AES */
    case 10: /* Twofish */
    case 11: case 12: case 13: /* Camellia */
      return 16;
    default:
      return 8;
    }
}

/**
 * create hexstring from a binary
 * @param str [String] string to convert
 * @return [String] string containing the hexadecimal values
 */
function hexstrdump(str) {
	if (str == null)
		return "";
  var r="";
  var e=str.length;
  var c=0;
  var h;
  while(c<e){
    h=str[c++].charCodeAt().toString(16);
    while(h.length<2) h="0"+h;
    r+=""+h;
  }
  return r;
};

function mpi_read (inp, pktlen) {
  var c1, c2,
      nbits, nbytes,
      mpi;
  c1 = inp.get();
  c2 = inp.get();

  nbits = c1 << 8 | c2 ;
  nbytes = parseInt((nbits + 7) / 8);

  mpi = String.fromCharCode(c1);
  mpi += String.fromCharCode(c2);
	mpi += inp.readString(nbytes);

	if (mpi.length > pktlen) 
	  throw "mpi larger than packet";
	return mpi;
}

function mpi_read_seckey(pubkey_algo, decodedMPIs) {
  var nskey = pubkey_get_nskey(pubkey_algo);
  var npkey = pubkey_get_npkey(pubkey_algo);
  var pktlen = decodedMPIs.length;

  var inp = new IOBuf(decodedMPIs);
  var skey = [];

  for (var i = 0; i < nskey - npkey; i++) {
    skey[i] = mpi_read (inp, pktlen);
    pktlen -= skey[i].length;
  }
  return skey;
}

function addmpi_len(mpi_str) {
  var msbpos = 1;
  for (var i = 7; i; i--)
    if (mpi_str.charCodeAt(0) & (1 << i)) {
      msbpos = i + 1;
      break;    
    }
  bitlen = ((mpi_str.length - 1) * 8) + msbpos;
  return u16_to_string(bitlen) + mpi_str;
}

var bin2str = function(bin) {
	var result = "";
	for (var i = 0; i < bin.length; i++) {
		result += String.fromCharCode(bin[i]);
	}
	return result;
};
var hexidump = function(str) {
	    var r="";
	    var e=str.length;
	    var c=0;
	    var h;
	    while(c<e){
	        h=str[c++].toString(16);
	        while(h.length<2) h="0"+h;
	        r+=""+h;
	    }
	    return r;
};

exports.hexidump = hexidump;
exports.bin2str = bin2str;
exports.pubkey_get_nskey = pubkey_get_nskey;
exports.pubkey_get_npkey = pubkey_get_npkey;
exports.pubkey_get_nsig = pubkey_get_nsig;
exports.md_test_algo = md_test_algo;
exports.pubkey_get_nenc = pubkey_get_nenc;
exports.pk_test_algo = pk_test_algo;

exports.addmpi_len = addmpi_len;
exports.mpi_read = mpi_read;
exports.mpi_read_seckey = mpi_read_seckey;
exports.openpgp_cipher_blocklen = openpgp_cipher_blocklen; 

exports.hexstrdump = hexstrdump;
exports.string_to_u32 = string_to_u32;
exports.string_to_u24 = string_to_u24;
exports.u32_to_string = u32_to_string;
exports.u32_to_array  = u32_to_array;
exports.u16_to_string = u16_to_string;
exports.atos = atos;
exports.stoa = stoa;
exports.atohex = atohex;
exports.hextoa = hextoa;
exports.stohex = stohex;

exports.write_packet_header = write_packet_header;

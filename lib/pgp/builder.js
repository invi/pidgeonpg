// # builder
//
// Builds OpenPGP format binary packets
//
const PGP = require("pgp/openpgpdefs");
const misc = require('util/misc');
const symcrypto = require('crypto/sym');
const {hashData} = require('crypto/hash');
const logger = require("util/logger").create("builder.js");


// ### encode_length(length)
//
// Encodes the given packet `length`
function encode_length(length) {
  result = "";
  if (length < 192) {
    result += String.fromCharCode(length);
  } else if (length > 191 && length < 8384) {
    /*
     * let a = (total data packet length) - 192 let bc = two octet
     * representation of a let d = b + 192
     */
    result += String.fromCharCode(((length - 192) >> 8) + 192);
    result += String.fromCharCode((length - 192) & 0xFF);
  } else {
    result += String.fromCharCode(255);
    result += String.fromCharCode((length >> 24) & 0xFF);
    result += String.fromCharCode((length >> 16) & 0xFF);
    result += String.fromCharCode((length >> 8) & 0xFF);
    result += String.fromCharCode(length & 0xFF);
  }
  return result;
}


// ## write_binary_signature
//
function write_binary_signature(sig) {
  var ret = "",
      sigPacket = sig.getPacket();
  
  ret += String.fromCharCode(sigPacket.version) +
         String.fromCharCode(sigPacket.sig_class) +
         String.fromCharCode(sigPacket.pubkey_algo) +
         String.fromCharCode(sigPacket.digest_algo) +
         misc.u16_to_string(sigPacket.hashed.data.length) +
         misc.atos(sigPacket.hashed.data) +
         misc.u16_to_string(sigPacket.unhashed.data.length) +
         misc.atos(sigPacket.unhashed.data) +
         misc.atos(sigPacket.digest_start) +
         misc.atos(sigPacket.data[0]);

  return write_packet_header(sig.getPacketType(), ret.length) + ret;
}

// ## write_encryptedintegrityprotecteddata_packet
//
function write_encryptedintegrityprotecteddata_packet(symmetric_algorithm, key, data, callback) {

  symcrypto.getPrefixRandom(symmetric_algorithm, function(prefixrandom) {
    try {
      var prefix = prefixrandom
          + prefixrandom.charAt(prefixrandom.length - 2)
          + prefixrandom.charAt(prefixrandom.length - 1);
      var tohash = data;
      tohash += String.fromCharCode(0xD3);
      tohash += String.fromCharCode(0x14);
      tohash += hashData(PGP.HASH.SHA1, prefix + tohash);
      var result = symcrypto.encrypt(prefixrandom,
          symmetric_algorithm, key, tohash, false).substring(0,
          prefix.length + tohash.length);
      var header = write_packet_header(18, result.length + 1)
          + String.fromCharCode(1);
      callback(null, header + result); 

    } catch (err) {
      callback(err);
    }
  });
}

// ## write_literal_packet
//
function write_literal_packet(_data) {
  var data = _data.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
  var filename = "msg.txt";
  var date = Math.floor(new Date().getTime() / 1000);
  var format = 't';
  var result = write_packet_header(11, data.length + 6
      + filename.length);
  result += format;
  result += String.fromCharCode(filename.length);
  result += filename;
  result += misc.u32_to_string(date);
  result += data;
  return result;
}

// ## write_onepasssignature_packet
//
function write_onepasssignature_packet(sig, nested) { 
  nested = nested || false;
  var res = "";
 
  res += write_packet_header(4,13);
  res += String.fromCharCode(3);
  res += String.fromCharCode(sig._sig.pkt.sig_class);
  res += String.fromCharCode(sig._sig.pkt.digest_algo);
  res += String.fromCharCode(sig.key.getAlgo());
  res += sig.getKeyId();
  if (nested)
    res += String.fromCharCode(0);
  else
    res += String.fromCharCode(1);
 
  return res;
}

function write_packet_header(tag_type, length) {
  /* we're only generating v4 packet headers here */
  var res = "";
  res += String.fromCharCode(0xC0 | tag_type);
  res += encode_length(length);
  return res;
}

// write_pub_key_packet(pubkey, esk_mpis)
//
function write_pub_key_packet(pubkey, esk_mpis) {

  var res = String.fromCharCode(3);
  res += pubkey.getKeyId();
  res += String.fromCharCode(pubkey.getAlgo());

  for (var i=0; i<esk_mpis.length; i++)
  {
    var len = esk_mpis[i].length * 8;
    res += String.fromCharCode(len >> 8);
    res += String.fromCharCode(len & 0xff);
    res += esk_mpis[i];
  }

  return write_packet_header(1, res.length) + res;
}

function write_pubkey_encryptedsessionkey_packet(encryption_cipher, session_key, key, callback) {
  try { 
    var sessionkeypacket = build_sessionkey_packet(encryption_cipher, session_key);
    var encryption_key = key.getEncryptionKey();
    encryption_key.encrypt(sessionkeypacket, function(encryptedsessionkey) {
      var res = write_pub_key_packet(encryption_key, encryptedsessionkey);
      callback(null, res);
    });
  } catch(err) {
    callback(err);
  }
}

function build_sessionkey_packet(symmalgo, sessionkey) {
  var checksum = misc.calc_checksum(sessionkey);

  var data = String.fromCharCode(symmalgo);
  data += sessionkey;
  data += String.fromCharCode(((checksum >> 8) >>> 0) & 0xFF);
  data += String.fromCharCode((checksum) & 0xFF);

  return data;
}


exports.build_sessionkey_packet = build_sessionkey_packet;
exports.write_binary_signature = write_binary_signature;
exports.write_encryptedintegrityprotecteddata_packet = write_encryptedintegrityprotecteddata_packet;
exports.write_literal_packet = write_literal_packet;
exports.write_onepasssignature_packet = write_onepasssignature_packet;
exports.write_pub_key_packet = write_pub_key_packet;
exports.write_pubkey_encryptedsessionkey_packet = write_pubkey_encryptedsessionkey_packet;

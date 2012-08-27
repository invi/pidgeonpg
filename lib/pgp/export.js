/**
 * @scope export
 */
const PGP = require('pgp/openpgpdefs.js');
const misc = require('util/misc.js');
const logger = require('util/logger').create("export.js");
const armor = require('encode/armor');

function write_public_packet(key) 
{
  var ret = "",
      kpkt = key.getPacket();

  ret += String.fromCharCode(kpkt.version) +
         misc.u32_to_string(kpkt.timestamp) +
         String.fromCharCode(kpkt.pubkey_algo);

  for (var i=0;i<kpkt.pkey.length;i++)
    ret += kpkt.pkey[i];

  //Only export public keys
  var pkttype;
  switch (key.getPacketType())
  {
    case PGP.PKT.SECRET_KEY:
    pkttype = PGP.PKT.PUBLIC_KEY;
    break;
    case PGP.PKT.SECRET_SUBKEY:
    pkttype = PGP.PKT.PUBLIC_SUBKEY;
    break;
    default:
    pkttype = key.getPacketType();
  }
  return misc.write_packet_header(pkttype, ret.length) + ret;
}

function write_secret_packet(key)  {

  var pkt = key.getPacket();
  var ret = String.fromCharCode(pkt.version) +
          misc.u32_to_string(pkt.timestamp) +
          String.fromCharCode(pkt.pubkey_algo);

  for (var i=0;i<pkt.pkey.length;i++)
    ret += pkt.pkey[i];

  ret += String.fromCharCode(pkt.ski.usage);

  if (key.isProtected()) {
    ret += String.fromCharCode(pkt.ski.algo);
    ret += String.fromCharCode(pkt.ski.s2k.mode);
    ret += String.fromCharCode(pkt.ski.s2k.hash_algo);
    if (pkt.ski.s2k.mode == 1 || pkt.ski.s2k.mode == 3) 
      ret += misc.atos(pkt.ski.s2k.salt);
    if (pkt.ski.s2k.mode == 3) 
      ret += String.fromCharCode(pkt.ski.s2k.count);
    ret += misc.atos(pkt.ski.iv);
    ret += pkt.skey[0];
  }
  else {
    var secmpis = "";
    for (var i=0;i<pkt.skey.length;i++) 
      secmpis += pkt.skey[i];

    var csum = 0;
    for (var i=0;i<secmpis.length;i++) 
      csum += secmpis.charCodeAt(i);
    csum %= 65536;

    ret += secmpis;
    ret += misc.u16_to_string(csum);
  }

  //Only export public keys
  var pkttype = key.getPacketType();

  return misc.write_packet_header(pkttype, ret.length) + ret;
}

function write_key_packets(key, secret) {
  var ret = "";
  
  for (var i=0;i<key.revsigs.length;i++) 
    ret += key.revsigs[i].write_packet();

  var uids = key.getUserIds();
  for (var i=0;i<uids.length;i++) {
    try {
      ret += misc.write_packet_header(uids[i].getPacketType(), 
                                      uids[i].getName().length);
      ret += uids[i].getName();
      var sigs = uids[i].revsigs.concat(uids[i].selfsigs.concat(uids[i].sigs));
      for (var j=0;j<sigs.length;j++) 
        ret += sigs[j].write_packet();
    }
    catch(e) {
      logger.error(e);
    }
  }

  var subkeys = key.subkeys;
  for (var i=0;i<subkeys.length;i++) {
    ret += secret ? write_secret_packet(subkeys[i]) : 
                    write_public_packet(subkeys[i]);
    var sigs = subkeys[i].revsigs.concat(subkeys[i].selfsigs);
    for (var j=0;j<sigs.length;j++)
    {
      ret += sigs[j].write_packet();
    }
  }
  return ret;
}

function export_key(key, secret)
{
  var ret = secret ? write_secret_packet(key) : write_public_packet(key);
  ret += write_key_packets(key, secret);
  return  ret;
}

exports.export_pubkey = function(armored) {
  if (typeof armored == "undefined") armored = true;
  var binkey = export_key(this, false);
  return armored ? armor.encode(binkey, PGP.ARMOR.PUBLICKEY) : binkey;
}

exports.export_seckey = function(armored) {
  if (typeof armored == "undefined") armored = true;
  var binkey = export_key(this, true);
  return armored ? armor.encode(binkey, PGP.ARMOR.PRIVATEKEY) : binkey;
}


//  function write_sig_subpkt(type, data)
//  {
//    var ret = "",
//        len = data.length;
//
//    if (len >= ((0xfe -192) << 8) + 0xff + 192)
//    { 
//      ret += String.fromCharCode(255);
//      ret += u32_to_string(len);
//    }
//    else if (len >= 192)
//    {
//      ret += String.fromCharCode((len >> 8) + 192);
//      ret += String.fromCharCode((len - 192) & 0xff);
//    }
//    else {
//      ret += String.fromCharCode(len);
//    }
//
//    ret += String.fromCharCode(type);
//    ret += data;
//    return ret;
//  }

const PGP = require("pgp/openpgpdefs");
const logger = require('util/logger').create('der.js');
const IOBuf = require('util/iobuf').IOBuf;
const misc = require('util/misc');
const rsa = require('crypto/asymmetric/rsa/rsa');
const base64Decode = require("api-utils/base64").decode;
const base64Encode = require("api-utils/base64").encode;

const DER_INTEGER = 0x02,
      DER_SEQUENCE = 0x30,
      DER_BITSTRING = 0x03,
      DER_OCTECTSTRING = 0x04,
      DER_NULL = 0x05,
      DER_OID = 0x00;

const OID_RSA = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00],
      OID_DSA = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01],
      OID_DH  = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01];

function DEREncode() {
  this.outout = [];
  this.derbuf = [];
  this.sequences = [];
}

DEREncode.prototype.wrap_len = function(arr) {
  var ret = [ ];
  var nbytes = arr.length;

  if (nbytes < 0xff/2) {
    ret.push(nbytes & 0xff);
  } else if (nbytes < 0xff) {
    ret[0] = 0x81;
    ret.push(nbytes & 0xff);
  } else if (nbytes < 0xffff) {
    ret[0] = 0x82;
    ret.push((nbytes >> 8) & 0xff);
    ret.push(nbytes & 0xff);
  } else {
    ret[0] = 0x83;
    ret.push((nbytes >> 16) & 0xff);
    ret.push((nbytes >> 8) & 0xff);
    ret.push(nbytes & 0xff);
  }
  return ret.concat(arr);
}

DEREncode.prototype.bitstring = function() {
  var buf = [0].concat(this.derbuf.slice(0));
  var ret = this._encode(buf, DER_BITSTRING);
  this.derbuf = [];
  return ret;
}

DEREncode.prototype.octectstring = function() {
  var buf = this.derbuf.slice(0);
  var ret = this._encode(buf, DER_OCTECTSTRING);
  this.derbuf = [];
  return ret;
}

DEREncode.prototype.sequence = function() {
  var buf = this.derbuf.slice(0);
  var ret = this._encode(buf, DER_SEQUENCE);
  this.derbuf = [];
  return ret;
}

DEREncode.prototype.concat = function(arr) {
  this.derbuf = this.derbuf.concat(arr);
}

DEREncode.prototype._encode = function(val, type) {
  return [type].concat(this.wrap_len(val));
}

DEREncode.prototype.encode = function(val, type) 
{
  switch (type) {
    case DER_OID:
      this.derbuf = this.derbuf.concat(val);
      break;
    default:
      this.derbuf = this.derbuf.concat(this._encode(val, type));
  }
}

DEREncode.prototype.toString = function() {
  return base64Encode(misc.atos(this.derbuf));
}


function RSAPrivate(pkey) {
  var byteLen = pkey[0].length - 2;
  try {
  var N  = misc.stohex(pkey[0].substr(2)),  
      E  = misc.stohex(pkey[1].substr(2)), 
      D  = misc.stohex(pkey[2].substr(2)), 
      P  = misc.stohex(pkey[3].substr(2)), 
      Q  = misc.stohex(pkey[4].substr(2)), 
      C  = misc.stohex(pkey[5].substr(2));
  } catch (e) {
    throw e;
  } 

  this.NN = N;
  this.EE = E;
  this.DD = D;
  this.PP = P;
  this.QQ = Q;
  this.CC = C;

  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = rsa.parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = rsa.parseBigInt(D,16);
    this.p = rsa.parseBigInt(P,16);
    this.q = rsa.parseBigInt(Q,16);
    this.dmp1 = this.d.mod(this.p.subtract(rsa.BigInteger.ONE));
    this.dmq1 = this.d.mod(this.q.subtract(rsa.BigInteger.ONE));
    this.coeff = this.q.modInverse(this.p);

    this.n = misc.stoa(pkey[0]).slice(2);
    this.e = misc.stoa(pkey[1]).slice(2);
    this.d = misc.stoa(pkey[2]).slice(2);
    this.p = misc.stoa(pkey[3]).slice(2);
    this.q = misc.stoa(pkey[4]).slice(2);

    var dmp1tmp = this.dmp1.toByteArray();
    var dmq1tmp = this.dmq1.toByteArray();
    var coefftmp = this.coeff.toByteArray();
    var dmp1 = [];
    var dmq1 = [];
    var coeff = [];

    var i=0;
    while (dmp1tmp[i]==0)
      i++;
    dmp1tmp = dmp1tmp.slice(i, i + byteLen / 2);

    i=0;
    while (dmq1tmp[i]==0)
      i++;
    dmq1tmp = dmq1tmp.slice(i, i + byteLen / 2);

    i=0;
    while (coefftmp[i]==0)
      i++;
    coefftmp = coefftmp.slice(i, i + byteLen / 2);

    while (dmp1tmp.length < byteLen / 2)
      dmp1tmp = [0].concat(dmp1tmp);
    while (dmq1tmp.length < byteLen / 2)
      dmq1tmp = [0].concat(dmq1tmp);
    while (coefftmp.length < byteLen / 2)
      coefftmp = [0].concat(coefftmp);

    for (var i=0; i<dmp1tmp.length; i++)
    {
      if (dmp1tmp[i] < 0)
      {
        dmp1tmp[i] = 256 + dmp1tmp[i];
      }
      if (dmq1tmp[i] < 0)
      {
        dmq1tmp[i] = 256 + dmq1tmp[i];
      }
      if (coefftmp[i] < 0)
      {
        coefftmp[i] = 256 + coefftmp[i];
      }

      dmp1.push( dmp1tmp[i]);
      dmq1.push( dmq1tmp[i]);
      coeff.push( coefftmp[i]);
    }

    this.DPP = misc.atohex(dmp1);
    this.DQQ = misc.atohex(dmq1);
    this.CC = misc.atohex(coeff);
    this.dmp1 = dmp1;
    this.dmq1 = dmq1;
    this.coeff = coeff;
  }
  else
    throw new Error("Invalid RSA private key");
}

function encodeRSAtoDER(pkey) {

  var der = new DEREncode();
  var rsaPrivate = new RSAPrivate(pkey);
  der.encode(OID_RSA, DER_OID);
  var oid = der.sequence();

  //byte array
  der.encode([0], DER_INTEGER);
  der.encode(rsaPrivate.n, DER_INTEGER);
  der.encode(rsaPrivate.e, DER_INTEGER);
  der.encode(rsaPrivate.d, DER_INTEGER);
  der.encode(rsaPrivate.p, DER_INTEGER);
  der.encode(rsaPrivate.q, DER_INTEGER);
  der.encode(rsaPrivate.dmp1, DER_INTEGER);
  der.encode(rsaPrivate.dmq1, DER_INTEGER);
  der.encode(rsaPrivate.coeff, DER_INTEGER);

  var primes = der.sequence();
  der.concat(primes);
  var os = der.octectstring();

  der.encode([0], DER_INTEGER);
  der.concat(oid);
  der.concat(os);

  var ret = der.sequence();
  return base64Encode(misc.atos(ret));
}

function encodeDSAtoDER(pkey)
{
  var der = new DEREncode();

  var prime = misc.stoa(pkey[0].substr(2)); 
  var subPrime = misc.stoa(pkey[1].substr(2));
  var base = misc.stoa(pkey[2].substr(2));
  var privateValue = misc.stoa(pkey[4].substr(2));

  der.encode(prime, DER_INTEGER);
  der.encode(subPrime, DER_INTEGER);
  der.encode(base, DER_INTEGER);

  var params = der.sequence();
  der.encode(OID_DSA, DER_OID);
  der.concat(params);
  var oid = der.sequence();

  der.encode(privateValue, DER_INTEGER);
  var os = der.octectstring();

  der.encode([0], DER_INTEGER);
  der.concat(oid);
  der.concat(os);
  var ret = der.sequence();

  return base64Encode(misc.atos(ret));
}

exports.encodeInteger = function(_ints) {
  var derencode = new DEREncode();
  derencode.encode(misc.stoa(_ints.substr(2)), DER_INTEGER); 
  var ret = derencode.sequence();
  return base64Encode(misc.atos(ret));
}

exports.encodePubKey = function(pkey, keyType) {
  var der = new DEREncode();
  var ret = null;
  switch (keyType) {
    case PGP.PUBKEY.ALGO.RSA:
    der.encode(OID_RSA, DER_OID);
    var oid = der.sequence();
    der.encode(misc.stoa(pkey[0].substr(2)), DER_INTEGER);
    der.encode(misc.stoa(pkey[1].substr(2)), DER_INTEGER);
    var primes = der.sequence();
    der.concat(primes);
    var os = der.bitstring();

    der.concat(oid);
    der.concat(os);
    ret = der.sequence();
    break;

    case PGP.PUBKEY.ALGO.DSA:
    var prime = misc.stoa(pkey[0].substr(2)); 
    var subPrime = misc.stoa(pkey[1].substr(2));
    var base = misc.stoa(pkey[2].substr(2));
    var privateValue = misc.stoa(pkey[3].substr(2));

    der.encode(prime, DER_INTEGER);
    der.encode(subPrime, DER_INTEGER);
    der.encode(base, DER_INTEGER);
    var params = der.sequence();
    der.encode(OID_DSA, DER_OID);
    der.concat(params);
    var oid = der.sequence();

    der.encode(privateValue, DER_INTEGER);
    var os = der.bitstring();

    der.concat(oid);
    der.concat(os);
    ret = der.sequence();
    break;
    default:
    throw new Error("INV_PUBKEY_ALGO");
  }

  return base64Encode(misc.atos(ret));
}

exports.encodeSecKey = function(pkey, pubkey_algo) {
  logger.func("encodeSecKey()");
  var ret = "";
  switch (pubkey_algo)
  {
    case PGP.PUBKEY.ALGO.RSA:
    ret = encodeRSAtoDER(pkey);
    break;
    case PGP.PUBKEY.ALGO.DSA:
    ret = encodeDSAtoDER(pkey);
    break;
    default:
    throw new Error("PGP.ERR.INV_ALGO");
  }
  return ret;
}

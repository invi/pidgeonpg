const PGP = require("pgp/openpgpdefs");
const logger = require('util/logger').create('der.js');
const IOBuf = require('util/iobuf').IOBuf;
const misc = require('util/misc');
const {BigInteger} = require('crypto/asymmetric/jsbn2.js');
const base64Decode = require("api-utils/base64").decode;
const base64Encode = require("api-utils/base64").encode;

const DER_INTEGER      = 0x02;
const DER_SEQUENCE     = 0x30;
const DER_BITSTRING    = 0x03;
const DER_OCTECTSTRING = 0x04;
const DER_NULL         = 0x05;
const DER_OID          = 0x00;

const OID_RSA = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00];
const OID_DSA = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];
const OID_DH  = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01];

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

function calc_rsa_mpis(pkey) {

  var D = misc.stohex(pkey[2].substr(2)); 
  var P = misc.stohex(pkey[3].substr(2)); 
  var Q = misc.stohex(pkey[4].substr(2)); 

  var B_d = new BigInteger(D,16);
  var B_p = new BigInteger(P,16);
  var B_q = new BigInteger(Q,16);
  var B_dmp1 = B_d.mod(B_p.subtract(BigInteger.ONE));
  var B_dmq1 = B_d.mod(B_q.subtract(BigInteger.ONE));
  var B_coeff = B_q.modInverse(B_p);

  return { 
    dmp1_mpi: B_dmp1.toMPI(), 
    dmq1_mpi: B_dmq1.toMPI(), 
    coeff_mpi: B_coeff.toMPI() 
  };
}

function encodeRSAtoDER(pkey) {
  var n = misc.stoa(pkey[0].substr(2)); 
  var e = misc.stoa(pkey[1].substr(2)); 
  var d = misc.stoa(pkey[2].substr(2)); 
  var p = misc.stoa(pkey[3].substr(2)); 
  var q = misc.stoa(pkey[4].substr(2)); 

  var {dmp1_mpi, dmq1_mpi, coeff_mpi} = calc_rsa_mpis(pkey);
  var dmp1 = misc.stoa(dmp1_mpi.substr(2)); 
  var dmq1 = misc.stoa(dmq1_mpi.substr(2)); 
  var coeff = misc.stoa(coeff_mpi.substr(2)); 

  var der = new DEREncode();
  der.encode(OID_RSA, DER_OID);

  var oid = der.sequence();
  //byte array
  der.encode([0], DER_INTEGER);
  der.encode(n, DER_INTEGER);
  der.encode(e, DER_INTEGER);
  der.encode(d, DER_INTEGER);
  der.encode(p, DER_INTEGER);
  der.encode(q, DER_INTEGER);
  der.encode(dmp1, DER_INTEGER);
  der.encode(dmq1, DER_INTEGER);
  der.encode(coeff, DER_INTEGER);

  var primes = der.sequence();
  der.concat(primes);
  var os = der.octectstring();

  der.encode([0], DER_INTEGER);
  der.concat(oid);
  der.concat(os);

  var ret = base64Encode(misc.atos(der.sequence()));
  return ret;
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

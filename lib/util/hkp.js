const XMLHttpRequest = require("xhr").XMLHttpRequest;

const ALGORITHMS = {
    1: 'RSA (Encrypt or Sign)',
    2: 'RSA Encrypt-Only',
    3: 'RSA Sign-Only',
    16: 'Elgamal (Encrypt-Only)',
    17: 'DSA (Digital Signature Standard)',
    18: 'Elliptic Curve',
    19: 'ECDSA',
    20: 'Elgamal (Encrypt or Sign)',
}

function formatDate(s) {
  var d = new Date(parseInt(s)*1000);
  try {
  return ("0" + d.getDate()).slice(-2) + "/" + ("0" + (d.getMonth() + 1)).slice(-2)  + "/" + (d.getYear() + 1900).toString().slice(-2);
  } catch(e) {
    console.log(e.toString());

  }
}

function Key(args) { //, keyid, algo, keylen, creation_date, expiration_date, flags) {
//    const _begin_header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
//    const _end_header = '-----END PGP PUBLIC KEY BLOCK-----'
    this.keyid = args[0];
    this.algo = ALGORITHMS[args[1]]; //XXX OutOfRangeException
    this.key_length = args[2];
    this.creation_date = args[3];
    this.expiration_date = args[4] != '' ? Date(args[4]): '';
    var flags = args[5] || '';
    this.revoked  = flags.indexOf('r') >= 0;
    this.disabled = flags.indexOf('d') >= 0;
    this.expired  = flags.indexOf('e') >= 0;
    this.uids= [];
}

Key.prototype.dump = function() {
  var key = {
    keyid: this.keyid, 
    short_id: this.keyid,
    type: true,
    algo: this.algo,
    key_length: this.key_length,
    creation_date: formatDate(this.creation_date),
    expiration_date: this.expiration_date,
    revoked: this.revoked,
    disabled: this.disabled,
    expired: this.expired,
    uids: []
  };
  for (var i=0; i< this.uids.length; i++)
    key.uids.push(this.uids[i].dump());
  return key;
}

function parse_response(response) {
  var result = [];
  try {
    var lines = response.split('\n');
    var  key = null;
    lines.shift();
    for (var i=0; i<lines.length; i++) {
      var items = lines[i].split(':');
      var type = items.shift();
      if (type == 'pub') {
        key = new Key(items);
        result.push(key);
      } else
        if (type == 'uid' && key)
          key.uids.push(new Uid(items));
    }
    for (var i=0; i<result.length;i++)
      result[i] = result[i].dump();
  } catch(e) {
    throw new Error("ERR_PARSING_HKP_REQUEST");
    result=[];
  }
  return result; 
}

function Uid(args) { //uid, creation_date, expiration_date, flags) {
  this.uid = decodeURI(args[0]);
  this.creation_date = args[1];
  this.expiration_date = args[2];
  flags = args[3] || '';
  this.revoked  = flags.indexOf('r') >=0;
  this.disabled = flags.indexOf('d') >=0;
  this.expired  = flags.indexOf('e') >=0;
}

Uid.prototype.dump= function() {
  return {
    uid: this.uid,
    creation_date: formatDate(this.creation_date),
    expiration_date: this.expiration_date,
    revoked:this.revoked,
    disabled:this.disabled,
    expired: this.expired
  };
}


function KeyServer(host, port) {
  this.host = 'http://' + host; 
  this.port = typeof port == 'undefined'? 11371: port;
}


KeyServer.prototype.search = function(query, callback, options) {
  if (typeof options == 'undefined')
    var options = {};
  var nm = options.nm || false;
  var exact = options.exact || false;
  var params = encodeURI(
    '?search=' + query + '&op=index' +
    '&options=mr' + (nm || false ? ',nm':'') +
    '&exact=' + (exact || false ? 'on':'off'));
  var request_url = this.host + ':' + this.port + '/pks/lookup' + params;
  var request = new XMLHttpRequest();
  request.onreadystatechange = function(res) { 
    try {
      if (request.readyState == 4)
        if (request.status == 200) {
          var keys = parse_response(request.responseText);
          callback(null, keys); 
        }
        else {
          var err = new Error(request.status + ":" + request.statusText);
          callback(err); 
        }
    } catch(e) {
      callback(err); 
    }
  }; 
  request.open("GET", request_url, true);
  request.send(null);
}

KeyServer.prototype.add = function(key, callback) {
  var request_url = this.host + ':' + this.port + '/pks/add?' + encodeURI('keytext="' + key + '"');
  var request = new XMLHttpRequest();
  request.onreadystatechange = function() { callback(request);};
  request.open("GET", request_url, true);
  request.send(null);
}

const label1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const label2 = "-----END PGP PUBLIC KEY BLOCK-----";
KeyServer.prototype.get = function(keyid, callback, options) {
  if (typeof options == 'undefined')
    var options = {};
  var nm = options.nm || false;
  var mr = options.exact || true;
  var params = encodeURI(
        '?search=' + (keyid.indexOf('0x') === 0 ? keyid: '0x' + keyid) +
        '&op=get' +
        '&options=mr' + (nm || false ? ',nm':''));
  var request = new XMLHttpRequest();
  var request_url = this.host + ':' + this.port + '/pks/lookup' + params;
  request.onreadystatechange = function () { 
    if (request.readyState == 4)
      if (request.status == 200) {
        var keydata = label1 + request.responseText.split(label1)[1].split(label2)[0] + label2;
        callback(null, keydata); 
      } else 
        callback(new Error(request.status));
  };
  request.open("GET", request_url, true);
  request.send(null);
}

exports.KeyServer = KeyServer;

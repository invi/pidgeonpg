// # ppgapp
// 
//     Stability: 2 - Unstable
// 
// Direct OpenPGP protocol operations and application using a predefined
// local key ring. To use this module use `require('ppgapp')`. Methods
// have asynchronous or synchronous forms.
// 
// The asynchronous form always take a completion callback as its last argument.
// The arguments passed to the completion callback depend on the method, but the
// first argument is always reserved for an exception. If the operation was
// completed successfully, then the first argument will be `null` or `undefined`.
// 
// When using the synchronous form any exceptions are immediately thrown.
// You can use try/catch to handle exceptions or allow them to bubble up.
// 
// Here is an example of the asynchronous version:
// 
//     var ppgapp = require('ppgapp');
// 
//     ppgapp.sign("Signed message with key", "B5E4BE82180EE2D9", function(err, enc) {
//       if (err) throw err;
//       console.log('following is showing encrypted message');
//       console.log(enc);
//     }
// 
// Here is a synchronous version:
// 
//     var ppgapp = require('ppgapp');
// 
//     ppgapp.find_key("0xB5E4BE82180EE2D9");
// 
// The tests for this module can be found [here](test/test-ppgappapp.html).

const PGP = require('pgp/openpgpdefs.js');
const logger = require('util/logger').create("ppgapp.js");
logger.stdout = true;
const {storage} = require('ring/storage');
const armor = require('encode/armor');
const misc = require('util/misc');
const {Key} = require('pgp/key');
const {Subkey} = require('pgp/subkey');
const {EncryptedMessage} = require('pgp/encryptedmessage');
const {ClearSignMessage} = require('pgp/clearsignmessage');
const {Message} = require('pgp/message');
const {parsekeys, parsekeysfile} = require("pgp/key-parse");
const {setLang, getStr} = require('util/lang');

// ## Object ppgapp

var ppgapp = {

  // ### importData(data, callback)
  // 
  // `data` binary or armored key block data as `string` 
  //
  // `callback` get two arguments `(err, keys)` where `keys` is an array 
  // of the merged keys into the key ring
  importData: function(filedata, callback) {
    var keys = parsekeys(filedata);
    var imported_keys = [ ];
    for (var i=0; i<keys.length; i++) 
      storage.importKey(keys[i], function(err, merged_key) {
        if (err) logger.error(err);
        imported_keys.push(merged_key.getFormatted());
        callback(merged_key.getFormatted());
        if (imported_keys.length == keys.length) 
          callback(null);
      });
  },

  // ### importFile(filename, [callback])
  // 
  // `filename` is a `string` containing key filename.
  //
  // `callback` first' argument is the merged key into the local key ring
  importFile: function (filename, callback) {
    var keys = parsekeysfile(filename);
    var imported_keys = [];
    for (var i=0; i<keys.length; i++) 
      storage.importKey(keys[i], function(err, merged_key) {
        if (err) { logger.error(err); return; };
        imported_keys.push(merged_key.getFormatted());
        if (imported_keys.length == keys.length) 
          callback(imported_keys);
      });
  },

  // ### generateKeypair(options, [callback])
  // 
  // Asynchronous key pair generation. 
  // 
  // The first argument, the `options` should be an object
  // containing several members. 
  //
  // Example:
  //
  //     var options = { 
  //       expireseconds: 0,
  //       name: "test name <test@ppgapp.org> (test comment)",
  //       keyType: PGP.PUBKEY.ALGO.RSA,
  //       keypairBits: 2048,
  //       subkeyType: PGP.PUBKEY.ALGO.RSA,
  //       subkeypairBits: 2048,
  //     }
  generateKeypair: function(options, callback) {
    Key.generate(options, function(err, key) {
      if (err) callback(err)
      else
        storage.importKey(key, function(err, imported_key) {
          if (err) callback(err);
          else callback(null, imported_key.getFormatted()); 
        });
    });
  },
  
  // ### revokeKey(keyid, reason, comment, callback)
  //
  // `reason` revocation reason value as `integer`
  //
  // `comment` optional revocation comment as `string`. May be empty string.
  revokeKey: function(keyid, reason, comment, callback) {
    try {
      logger.debug("revokeKey");
      var key = storage.fetchKey(keyid);
      key.generateRevocation(reason, comment, function(err) {
        try {
          if (err) callback(err) 
          else callback(null, key.getFormatted());
        } catch(err) { callback(err) }
      });
    } catch(err) { callback(err) }
  },
  
  // ### revokeSubkey(keyid, reason, comment, callback)
  //
  // `reason` revocation reason value as `integer`
  //
  // `comment` optional revocation comment as `string`. May be empty string.
  revokeSubkey: function(keyid, reason, comment, callback) {
    try {
      var key = storage.fetchKey(keyid);
      var subkey = key.getKey(misc.atos(misc.hextoa(keyid)));
      subkey.generateRevocation(reason, comment, function(err) {
        if (err) callback(err) 
        else callback(null, key.getFormatted(), subkey.getFormatted());
      });
    } catch(err) { callback(err) };
  },
  
  // ### revokeUserId(keyid, uid\_index, reason, comment, [callback])
  //
  // `uid\_index` revocation reason value as `integer`
  //
  // `reason` revocation reason value as `integer`
  //
  // `comment` optional revocation comment as `string`. May be empty string.
  revokeUserId: function(keyid, uid_index, reason, comment, callback) {
    try {
      var key = storage.fetchKey(keyid);
      var uid = key.uids[uid_index];
      uid.generateRevocation(reason, comment, function(err) {
        if (err) callback(err);
        else callback(null, key.getFormatted(), uid.getFormatted());
      });
    } catch(err) { callback(err) };
  },

  editUserId: function(keyid, uid_index, expireseconds, callback) {
    try {
      var key = storage.fetchKey(keyid);
      var uid = key.uids[uid_index];
      uid.generateSelfSig(expireseconds, function(err) {
        if (err) callback (err);
        else callback(null, key.getFormatted(), uid.getFormatted());
      });
    } catch(err) { callback(err) };
  },

  // ### generateUserId(keyid, options, [callback])
  // 
  // `options` example:
  //
  //      var options =  { name : "uid full name", expireseconds: 0 };
  generateUserId: function(keyid, options, callback) {
    try {
      var key = storage.fetchKey(keyid);
      key.generateUserId(options.name, options.expireseconds, function(err, uid) {
        if (err) callback(err)
        else { callback(null, key.getFormatted(), uid.getFormatted()); }
      });
    } catch(err) {
      callback(err);
    }
  },

  // ### generateSubkey(keyid, options, [callback])
  //
  //     var options = { subkeyType: PGP.PUBKEY.RSA,
  //                     keypairBits: 2048
  //                     expireseconds: 0 }
  generateSubkey: function(keyid, options, callback) {
    try {
      var key = storage.find(keyid);
      var {subkeyType, keypairBits, expireseconds} = options;
      key.generateSubkey(subkeyType, keypairBits, expireseconds, function(err, subkey) {
        try {
          if (err) callback(err)
          else callback(null, key.getFormatted(), subkey.getFormatted());
        } catch(err) { callback(err); }
      });
    } catch (err) {
      callback(err);
    }
  },

  // ### signUserId(keyid, uid\_index, callback)
  // 
  // Generate User Id signature for the given index
  signUserId: function(keyid, uid_index, callback) {
    try {
      var defaultkey = storage.fetchDefaultKey();
      var key = storage.fetchKey(keyid);
      var uid = key.uids[uid_index];

      uid.signUserId(defaultkey, function(err) {
        if (err) callback(err) 
        else callback(null, key.getFormatted());
      });
    } catch(err) { callback(err); }
  },
  
  // ### sign(msgdata, keyid, [callback])
  //
  // Creates an armored cleartext signatures for given string
  sign: function(msgdata, keyid, callback) {
    try {
      logger.func("sign");
      var msg = new Message(msgdata);
      msg.sign(keyid, function(err, msg) {
        if (err) callback(err);
        else callback(null, msg);
      });
    } catch(err) { callback(err); }
  },
  
  // ### encrypt(msgdata, ekeyid, skeyid, callback)
  // 
  // Creates an armored encrypted message 
  encrypt: function(msgdata, ekeyids, skeyids, callback) {
    try {
      var msg = new Message(msgdata);
      msg.encrypt(ekeyids, skeyids, function(err, msg) {
        if (err) callback(err);
        else callback(null, msg);
      });
    } catch(err) {
      callback(err);
    }
  },
  
  // ### decrypt(msgdata, callback)
  // 
  // Decrypts the given armored or binary  encrypted message
  // 
  // `msgdata` Encrypted message data as string
  //
  // `callback` (err, encmsg) The second argument of the callback
  // return the armored encrypted message
  decrypt: function(msgdata, callback) {
    try {
      var emsg = EncryptedMessage.create(msgdata);
      emsg.decrypt(function(err, msg) {
        callback(err, msg, emsg.key.getKeyIdStr());
      });
    } catch(err) {
      callback(err);
    }
  },
  
  // ### verify(msgdata, [callback])
  // 
  // `msgdata` Message data as `string`
  //
  // `callback` (err, data)
  verify : function Verify(msgdata, callback) {
    try {
      logger.func("verify");
      var smsg = ClearSignMessage.create(msgdata);
      smsg.verify(function(err, valid, issuerkeyid) {
        if (err) callback(err, false, issuerkeyid)
        else callback(null, valid, issuerkeyid);
      });
    } catch(err) { callback(err); }
  },
  
  removeAllKeys: storage.removeAllKeys,
  // ### removeKey(keyid)
  // Removes the given key from the local key ring
  // 
  // `keyidstr` keyidstr Key ID in hexadecimal long format
  //
  // Returns `null` if success, otherwise an error is thrown
  removeKey: storage.removeKey,

  // ### removeUserId(keyid, uid_index)
  // Removes the given User ID key from the local key ring
  // 
  // `keyid` Key ID in hexadecimal long format
  // `uid_index` UserId index to remove
  //
  // Returns `null` if success, otherwise an error is thrown
  removeUserId: storage.removeUserId,

  // ### removeSubKey(keyid) 
  // Removes subkey from local key ring
  // 
  // `keyid` Key ID in hexadecimal long format
  // 
  // Return the found key, false otherwise
  removeSubkey: storage.removeSubkey,

  // ### findKey(keyid) 
  // 
  // `keyid` Key ID in hexadecimal long format
  // 
  // Returns the found key, false otherwise
  findKey: function(keyid) {
    var key = storage.find(keyid);
    return key.getFormatted();
  },

  // ### exportPublic(keyids) 
  // 
  // `keyids` array of Key IDs in hexadecimal long format
  // 
  // Return the exported keys as string, false otherwise
  exportPublic: function(keyids) {
    var bin_keys = "";
    for (var i=0;i<keyids.length;i++) {
      var key = storage.find(keyids[i]);
      bin_keys += key.export_pubkey(false);
    }
    return armor.encode(bin_keys, PGP.ARMOR.PUBLICKEY);
  },

  // ### exportSecret(keyid) 
  // 
  // `keyid` Key ID in hexadecimal long format
  // 
  // Return the exported secret key as string, false otherwise
  exportSecret: function(keyid) {
    var key = storage.find(keyid);
    return key.export_seckey();
  },
  
  // ### getPublicKeys()
  // Retreives all public keys from local key ring
  getPublicKeys: storage.getPublicKeys,

  // ### getAllKeys()
  // Retreives all keys from local key ring
  getAllKeys: storage.getAllKeys,

  // ### getDefaultKeyId()
  // Return the default keyid
  getDefaultKeyId: storage.getDefaultKeyId,

  // ### setDefaultKeyId(keyid)
  // `keyid` to set as default
  setDefaultKeyId: storage.setDefaultKeyId,
}

exports.ppgapp = ppgapp;

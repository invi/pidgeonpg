var ss = require("simple-storage");
const logger = require('util/logger').create('storage.js');
logger.stdout = true;
const PGP = require("pgp/openpgpdefs");
const Key = require('pgp/key').Key;
const misc = require("util/misc");
const {prompt} = require("util/prompt");
const update_key = require("ring/update-key").update_key;
const {setLang, getStr} = require('util/lang');

// Initialize default options
ss.storage = ss.storage || {};
ss.storage.keyring = ss.storage.keyring || [];
ss.storage.options = ss.storage.options || {};
ss.storage.options.defaultkey = ss.storage.options.defaultkey || "";
ss.storage.options.lang = ss.storage.options.lang || "en";
ss.storage.options.keyserver = ss.storage.options.keyserver || "keyserver.ubuntu.com";
setLang(ss.storage.options.lang || "en");

// Helper functions
function format_keylist(key_list) {
  var formatted = [];
  for (var i=0; i< key_list.length; i++)
    formatted.push(format_key(key_list[i]));

  return formatted;
}

function format_key(key) {
  var k = Key.load(key, true);
  return k.getFormatted();
}

var Storage = {
  // ### setDefaultKeyId(keyid)
  //
  // `keyid` is a hex `string` with the key Id to set as default.
  //
  // Error is thrown is key doesn't exist in the local key ring.
  setDefaultKeyId: function(keyidstr) {
    if (Storage.fetchKey(keyidstr) != false) {
      ss.storage.options.defaultkey = keyidstr;
      logger.debug("Default key Id: " + keyidstr);
    }
  },
  
  // ### set_options(key, value)
  //
  // `key` is a `string` specifying the options to set.
  //
  // `value` is a `string`.
  set_option: function(key, value) {
    logger.debug("Storage: Setting option (key=%s value=%s", key, value);
    if (key == "defaultkey")
      this.setDefaultKeyId(value);
    else 
      if (key in ss.storage.options)
        ss.storage.options[key] = value;
    else
      throw "Option not available";
  },
  
  // ### get_options(key)
  //
  // `key` is a `string` specifying the options to return.
  get_option: function(key) {
    if (key in ss.storage.options) {
      logger.debug("Storage: Getting option (key=" + key + " value=" + ss.storage.options[key] + ")");
      return ss.storage.options[key];
    } else
      throw "Option not available";
  },
  
  // ### get_all_options()
  //
  // Returns all options
  get_all_options: function() {
    return ss.storage.options;
  },
  
  // ### cleantest()
  //
  // This method is used for running tests with a blank local key ring.
  cleantest: function() {
    ss = {};
    ss.storage = {};
    ss.storage.keyring = [];
    ss.storage.options = {};
    ss.storage.options.defaultkey = "";
    ss.storage.options.lang = "en";
    ss.storage.options.keyserver = "http://keyserver.ubuntu.com";
    setLang("en");
  },
  
  // ### removeAll()
  //
  // Removes all keys from local key ring and clears default key.
  removeAllKeys: function() {
    logger.debug("[Storage] Deleting all keys from keyring");
    var numkeys = ss.storage.keyring.length;
    //for (var i=0;i<ss.storage.keyring.length;i++) {
    //  delete ss.storage.keyring[i];
    //}
    ss.storage.keyring = [ ];
    ss.storage.defaultkey = "";
    return numkeys;
  },
  
  fetchDefaultKey: function() {
    var defaultkey = this.find(this.getDefault());
    if (!defaultkey) throw new Error("Default key could not be loaded");
    return defaultkey;
  },

  // ### getDefault()
  //
  // Returns the selected default `Key object` instance.
  getNumKeys: function() {
    return ss.storage.keyring.length;
  },
  
  // ### getDefault()
  //
  // Returns the selected default `Key object` instance.
  getDefault: function() {
    return ss.storage.options.defaultkey;
  },
  
  // ### add(key)
  //
  // Adds new or already existing key to the local key ring.
  //
  // `key` is a `Key object` instance.
  //
  // Returns the mesged key `Key object` instance.
  add: function(key) {
    var foundkey;
    if (!(foundkey=this.find(key.getKeyId()))) {
      logger.debug("Storage.add new key: %s", key.getKeyId());
      key.status.ringstatus = PGP.KEYSTATUS.NEW;
      ss.storage.keyring.push(key._key);
      return key;
    } else {
      logger.debug("Storage.add update key: %s", key.getKeyIdStr());
      var updatedkey = update_key(key, foundkey);
      this.replace(updatedkey);
      return updatedkey;
    }
  },
  
  // ### update_key(key)
  //
  // Merges and updates the given key in the local key ring.
  // If key is not found an error is thrown.
  //
  // `key` is a `Key object` instance.
  //
  // Returns the merged and updated key.
  update_key: function(key) {
    var foundkey;
    if (!(foundkey=this.find(key.getKeyId()))) {
      logger.debug("Key not found");
      throw new Error("Bug: Key to be updated not found in key ring");
    } else {
      var updatedkey = update_key(key, foundkey);
      this.replace(updatedkey);
      return this.find(updatedkey.getKeyId()) 
    }
  },
  
  // ### import\_key(key, [callback])
  // 
  // Imports `key` instance. Verifies signatures and 
  // updates the local key ring the merged key.
  // 
  // `key` Key class instance of a parsed key
  //
  // `callback` first' argument is the merged key into the local key ring
  importKey: function(key, callback) {
    var self = this;
    key.verify(function(err) {
      try {
        if (err) throw err;
        var updated_key = self.add(key);
        if (typeof callback == "function")
          callback(null, updated_key);
      } catch(_err) { callback(_err); }
    });
  },
  
  // ### remove(keyidstr)
  //
  // Removes a key from the local key ring
  //
  // `keyidstr` as hex `string`
  removeKey: function(keyidstr) {
    var keyid = misc.atos(misc.hextoa(keyidstr));
    if (keyidstr == Storage.getDefault()) {
      var ret = prompt.confirm("Alert", "¿Do you really want to remove your default key?");
      if (ret == 0)
        ss.storage.options.defaultkey = "";
      else
        return false;
    }
    for (var i=0; i<ss.storage.keyring.length; i++) {
      if (ss.storage.keyring[i].pkt.keyid == keyid) {
        ss.storage.keyring.splice(i, 1);
        logger.debug("Removed key with ID %s from keyring", keyidstr);
        return true;
      }
    }
    logger.debug("Couldn't remove key with ID %s from keyring", keyidstr);
    return false;
  },
  
  // ### remove_uid(keyidstr)
  //
  // Removes a key from the local key ring
  //
  // `keyidstr` as hex `string`
  removeUserId: function(keyidstr, uid_num) {
    var keyid = misc.atos(misc.hextoa(keyidstr));
    for (var i=0; i<ss.storage.keyring.length; i++) {
      if (ss.storage.keyring[i].pkt.keyid == keyid) {
        ss.storage.keyring[i].uids.splice(uid_num, 1);
        return true;
      }
    }
    return false;
  },
  
  // ### remove_subkey(subkeyidstr)
  //
  // Removes a key from the local key ring
  //
  // `keyidstr` as hex `string`
  removeSubkey: function(subkeyidstr) {
    var subkeyid = misc.atos(misc.hextoa(subkeyidstr));
    var keyid = Storage.find(subkeyid).getKeyId();
    for (var i=0; i<ss.storage.keyring.length; i++) 
      if (ss.storage.keyring[i].pkt.keyid == keyid) 
        for (var j=0; j<ss.storage.keyring[i].subkeys.length; j++) 
          if (ss.storage.keyring[i].subkeys[j].pkt.keyid == subkeyid) {
            ss.storage.keyring[i].subkeys.splice(j, 1);
            return Key.load(ss.storage.keyring[i], true);
          }
    return false;
  },
  
  // ### find(keyid)
  // Finds the `keyid` and returns the `Key object`, otherwise returns false.
  find: function(keyid) {
    for (var i=0; i<ss.storage.keyring.length; i++)   {
      var ikey = ss.storage.keyring[i];
      if (ikey.pkt.keyid == keyid || ikey.pkt.keyid_str == keyid)
      {
        return Key.load(ikey, true);
      }
      for (var j=0; j<ikey.uids.length; j++) {
        var name = ikey.uids[j].pkt.name;
        if (name.indexOf(keyid) > 0)
          return Key.load(ikey, true);
      }
      for (var j=0; j<ikey.subkeys.length; j++) {
        var jkey = ikey.subkeys[j];
        if (jkey.pkt.keyid == keyid || jkey.pkt.keyid_str == keyid)
        {
          return Key.load(ikey, true);
        }
      }
    }
    return false;
  },
  
  // ### replace(key)
  // `key` to be replaced in the local ring.
  replace: function(key) {
    for (var i=0; i<ss.storage.keyring.length; i++) {
      var ikey = ss.storage.keyring[i];
      if (ikey.pkt.keyid == key.getKeyId()) {
        ss.storage.keyring[i] = key._key;
        return true;
      }
    }
    return false;
  },
  
  // ### search(text)
  // XXX Not tested
  search: function(text) {
    var results = [ ];
    var rex = new RegExp(text, "i");
    for (var i=0; i<ss.storage.keyring.length; i++) {
      var ikey = ss.storage.keyring[i];
      var keyidstr = ikey.kpkt.keyid[1].toString(16) + ikey.kpkt.keyid[0].toString(16);
      var res;
      res = rex.exec(keyidstr)
      if (res) results.push(ikey);
      for (var j=0; j<ikey.uids.length; j++) {
        res = rex.exec(ikey.uids[j].name);
        if (res) results.push(ikey);
      }
      for (var j=0; j<ikey.secsubkeys.length; j++) {
        jkey = ikey.secsubkeys[j];
        keyidstr = jkey.keyid[1].toString(16) + jkey.keyid[0].toString(16);
        res = rex.exec(keyidstr);
        if (res) results.push(ikey);
      }
    }
    return results;
  },
  
  // ### fetchKey()
  // `keyid` Key Id in binary or hex `string`.
  //
  // Returns found key, otherwise error is thrown.
  fetchKey: function(keyid) {
    var key = this.find(keyid);
    if (!key) { throw "Can't find key with ID: " + keyid }
    return key;
  },
  
  // ### getAllKeys()
  // Returns all keys as an `array` with formatted fields.
  getAllKeys: function() {
    return format_keylist(ss.storage.keyring);
  },
  
  // ### getPublicKeys()
  // Returns only public keys with formatted fields.
  getPublicKeys: function() {
    var keys = []; 
    for (var i=0; i < ss.storage.keyring.length; i++) {
      var key = Key.load(ss.storage.keyring[i], true);
      if (key.isPublic())
        keys.push(key._key);
    }
    return format_keylist(keys);
  },
  
  // ### getPrivateKeys()
  // Returns only private keys with formatted fields.
  getPrivateKeys: function() {
    var keys = []; 
    for (var i=0; i < ss.storage.keyring.length; i++)   {
      var key = Key.load(ss.storage.keyring[i], true);
      if (key.isSecret())
        keys.push(key._key);
    }
    return format_keylist(keys);
  }
}

exports.storage = Storage;

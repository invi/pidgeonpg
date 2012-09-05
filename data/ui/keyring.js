function subscribeUpdates() {
  function updateSelects(selects, key) {
    for (var i=0;i<selects.length;i++) {
      var ele = selects[i];
      var content = "[" + key.short_id + "] " + key.uids[0].name;
      var children = ele.childNodes;
      if (children.length == 1) 
        children[0].textContent = getStr("select_key");

      for (var i=0;i<children.length;i++) {
        if (children[i].value == key.id) {
          children[i].textContent = content;
          return;
        }
      }
      addOption(ele, content, key.id, false);
    }
  }
  function removeSelects(selects, key) {
    for (var i=0;i<selects.length;i++) {
      var ele = selects[i];
      var children = ele.childNodes;
      for (var i=0;i<children.length;i++) {
        if (children[i].value == key.id) {
          if (children.length == 2)
            children[0].textContent = getStr("no_keys");
          ele.removeChild(children[i]);
          return;
        }
      }
    }
  }
  function updateKeyList(keylist, key, remove) {
    var found = false;
    for (var i=0;i<keylist.length;i++) 
      if (keylist[i].id == key.id) {
        found = true;
        if (remove) {
          keylist.splice(i, 1);
          return true;
        } else 
          keylist[i] = key;
      }
    if (!found && !remove) keylist.push(key);
    return false;
  }
  function updateKeyListAndSelects(listname, key, remove) {
    updateKeyList(Keyring[listname], key, remove) 
    if (remove)
      removeSelects(Keyring[listname+"_subs"], key);
    else 
      updateSelects(Keyring[listname+"_subs"], key);
  }
  function updateKey(res) {
    var key = res.key;
    updateKeyListAndSelects("encryptionkeys", key, !key.valid);
    if (key.secret) 
      updateKeyListAndSelects("signingkeys", key, !key.valid);
    updateKeyListAndSelects("allkeys", key, false);
  }
  function removeKey(key) {
    log_debug("Remove key " + key.id);
    updateKeyListAndSelects("encryptionkeys", key, true);
    if (key.secret) 
      updateKeyListAndSelects("signingkeys", key, true);
    updateKeyListAndSelects("allkeys", key, true);
  }

  ON("pgp-key-imported", function(res) {
    var key = res.key;
    updateKey(res);
  });
  ON("pgp-updated-uid-selfsig", updateKey);
  ON("pgp-keyring-deleted-uid", updateKey);
  ON("pgp-keyring-deleted-subkey", updateKey);
  ON("pgp-keyring-deleted-all-keys", function() {
    try {
      for (var i=0;i<Keyring.allkeys.length;i++) 
        removeKey(Keyring.allkeys[i]);
    } catch(err) {
      log_error(err);
    }
  });
  ON("pgp-keyring-deleted-keys", function(res) {
    try {
      for (var i = 0; i < res.deleted_keys.length; i++) 
        removeKey(Keyring.get(res.deleted_keys[i]));
    } catch(err) {
      log_error(err);
    }
  });
  ON("pgp-option-set-defaultkey", function(defaultkeyid) {
    Keyring.defaultKeyId = defaultkeyid;
    for (var i=0;i<Keyring.defaultkey_subs.length;i++) {
      var selele  = Keyring.defaultkey_subs[i];
      fillSelect(selele, Keyring.signingkeys, defaultkeyid);
      //for (var j=1;j<selele.childNodes.length;j++) {
      //  var text = selele.childNodes[j].textContent;
      //  if (text.substr(0,1) == "*") 
      //    selele.childNodes[j].textContent = text.substr(2);
      //  if (Keyring.signingkeys[j-1].id == defaultkeyid) 
      //  {
      //  console.log(Keyring.signingkeys[j-1].id , defaultkeyid, text);
      //    selele.childNodes[j].textContent = "* " + text;
      //  }
      //}
    }
  });
}
var Keyring = {
  loaded: false,
  allkeys: null,
  signingkeys: null,
  encryptionkeys: null,
  get: function(id) {
    for (var i=0;i<Keyring.allkeys.length;i++) {
      if (Keyring.allkeys[i].id == id)
        return Keyring.allkeys[i];
    }
    return false;
  },
  jumpToKey: function(id) {
    sections.close_dialog();
    var keys = document.body.querySelector("ul[name='list']").childNodes;
    var h = 0;
    for (var i=0; i<keys.length; i++) {
      var keybox = keys[i].childNodes[0];
      if (keybox.id == "key-" + id) break;
      h+=parseInt(window.getComputedStyle(keybox).height.split("px")[0]);
    }
    window.scrollTo(0, h);
  },
  format_keylink: function(id) {
    var key = this.get(id);
    if (key) {
      var link = document.createElement("a")
      link.className = "keylink";
      link.textContent =  key.short_id + " " + key.uids[0].name;
      link.href = "#";
      link.name = id;
      link.setAttribute("onclick", "return false;");
      return link.outerHTML;
    } else 
      return ""
  },
  update: function(key) {
    var found = null;
    if (found=this.get(key.id)) {
    }
  },
  init: function(target_ele, defaultKeyId, callback) {
    this.defaultKeyId = defaultKeyId || null;
    ONCE("pgp-fetched-keyring", function(_keylist) {
      Keyring.allkeys = [];
      Keyring.signingkeys = [];
      Keyring.encryptionkeys = [];
      for (var i=0; i<_keylist.length; i++) {
        var key = _keylist[i];
        Keyring.allkeys.push(key);
        if (key.valid) 
          Keyring.encryptionkeys.push(key);
        if (key.secret && key.valid)
          Keyring.signingkeys.push(key);
      }
      subscribeUpdates(); 
      Keyring.loaded = true;
      callback();
    });
    EMIT("pgp-fetch-keyring");
  },
  subscribeSelect: function(selectele, typeofkeys) {
    var keys = Keyring[typeofkeys];
    Keyring[typeofkeys+"_subs"].push(selectele);
    if (typeofkeys == "signingkeys") {
      Keyring['defaultkey_subs'].push(selectele);
      fillSelect(selectele, keys, Keyring.defaultKeyId);
    } else {
      fillSelect(selectele, keys, false);
    }
  },
  signingkeys_subs: [],
  allkeys_subs: [],
  encryptionkeys_subs: [],
  defaultkey_subs: [],
  defaultKeyId: null,
};

function Keyview(key, target_ele, str) {
  this.key = key;
  this.target = target_ele;
  this.title = "";
  this.uid_views = [];
  this.subkey_views = [];
  this.tabs = null;
  this.editable = false;
  this.selectable = false;
  this.str = str;
  this.updated = false;
  this.selected = false;
  this.expanded = false;
  this.box = undefined;
}

Keyview.template = new EJS({
  url: './templates/key_template.ejs',
  type: '['
});

Keyview.create = function(key, target_ele, editable, selectable, expanded) {
  var keyview = new Keyview(key, target_ele, strings);
  keyview.editable = editable || false;
  keyview.selectable = selectable || false;
  keyview.expanded = expanded || false;
  return keyview.init();
}

Keyview.prototype.init = function() {
  var self = this;
  this.box = Box.create(this.target, "key-" + this.key.id, this.makeTitle(), "", {selectable: this.selectable, expanded: this.expanded, expandable: true});
  this.box.ele.id = "key-" + this.key.id;
  if (this.selectable) 
    this.box.addEventListener("onselect", function() {
      self.selected = evt.target.checked;
    });
  this.box.addEventListener("onopen", function() {
    self.update(self.key);
    self.updated = true;
  });
  return this;
}
Keyview.prototype.setSelected = function(selected) {
  this.box.setSelected(selected);
}

Keyview.prototype.makeTitle = function(notescaped) {
  this.title = "";
  var keytype = this.key.secret ? "sec" : "pub";
  switch (this.key.algo.substr(0,1)) {
    case "R": 
      this.title += "R";
      break;
    case "D": 
      this.title += "D";
      break;
    case "E": 
      this.title += "g";
      break;
    default:
      this.title += "?";
  }
  var style = "";
  this.title = "<span class=\"keyid " + keytype + "\">" + keytype + " </span>&nbsp; <span class=\"keyid\">" + this.key.short_id + "</span>";
  if (this.key.revoked) 
    this.title += "<span class=\"invalid_key\">" + getStr("revoked").substr(0,1).toUpperCase() + "</span>";
  else if (this.key.expired)
    this.title += "<span class=\"invalid_key\">" + getStr("expired").substr(0,1).toUpperCase() + "</span>";
  else if (!this.key.valid)
    this.title += "<span class=\"invalid_key\">" + getStr("invalid").substr(0,1).toUpperCase() + "</span>";
  else
    this.title += "<span class=\"invalid_key\">&nbsp;</span>";

  if (this.key.uids.length) 
    this.title += "<span class=\"keytitle\">" + escapeHTML(this.key.uids[0].name) + "</span>";
  return this.title;
}

Keyview.prototype.show_createsub = function() {
  var self = this;
  var tab = this.tabs.get("key-createsub");
  if (tab.ele==null) return;
  var createsub_button = tab.ele.querySelector("button[name='create-sub']");
  var key_type = tab.ele.querySelector("#pgp-genkey-key-type");
  var key_length = tab.ele.querySelector("#pgp-genkey-key-length");
  var expiredate = tab.ele.querySelector("#expiredate");
  var expire_format = tab.ele.querySelector("#expiredateformat");
  var inputs = tab.ele.querySelectorAll("input");
  expiredate.disabled = (expire_format.value == "never");
  for (var i=0;i<inputs.length;i++) {
    inputs[i].onkeypress = function(evt) {
      if (evt.keyCode == 13) {
        createsub_button.onclick();
      }
    }
  }
  key_type.onchange = function(evt) {
    key_length.innerHTML = "<option value='1024'>1024</option>";
    if (evt.target.value == "RSA") 
      key_length.innerHTML += "<option value='2048' selected='selected'>2048</option>" +
                              "<option value='4096'>4096</option>";
  }
  expire_format.onchange = function(evt) { 
    expiredate.disabled = (evt.target.value == "never");
  }
  createsub_button.onclick = function(e) {
    try {
      if (!expiredateValidation(expire_format.value, expiredate)) return;
      createsub_button.disabled = true;
      key_type.disabled = true; 
      key_length.disabled = true;
      expiredate.disabled = true;
      expire_format.disabled = true;
      var expireseconds = getExpireSeconds(expire_format.value, expiredate.value)
      var options = { 
        expireseconds: expireseconds,
        expire_format: expire_format.value,
        keyType : (key_type.value == "RSA" ? ALGO.RSA: ALGO.ELGAMAL_E),
        subkeyType : (key_type.value == "RSA" ? ALGO.RSA: ALGO.ELGAMAL_E),
        keypairBits : parseInt(key_length.value)
      }
      ONCE("pgp-created-subkey", function (res) {
        self.update(res.key);
        notify.error(res.msg);
      });
      EMIT("pgp-create-subkey", { keyid:self.key.id, options:options});
    } catch(e) {
      notify.error(e.toString());
    }
  }
}

Keyview.prototype.show_createuid = function() {
  var self = this;
  var tab = this.tabs.get("key-createuid");
  if (tab.ele==null) return;
  var createuid_button = tab.ele.querySelector("button[name='create-uid']");
  var revoke_msg = tab.ele.querySelector("[name='createuid-message']");
  var email = tab.ele.querySelector("#email");
  var name = tab.ele.querySelector("#name");
  var comment = tab.ele.querySelector("#comment");
  var expiredate = tab.ele.querySelector("#expiredate");
  var expire_format = tab.ele.querySelector("#expiredateformat");
  var inputs = tab.ele.querySelectorAll("input");
  for (var i=0;i<inputs.length;i++) {
    inputs[i].onkeypress = function(evt) {
      if (evt.keyCode == 13) {
        createuid_button.onclick();
      }
    }
  }
  expire_format.onchange = function(evt) { 
    expiredate.disabled = (evt.target.value == "never");
  }
  createuid_button.onclick = function(e) {
    try {
      var valid_email = emailValidation(email)
      var valid_expiredate = expiredateValidation(expire_format.value, expiredate);
      if (!valid_email || !valid_expiredate) return;
      var expireseconds = getExpireSeconds(expire_format.value, expiredate.value)
      var uid_name = buildUserId(name.value, comment.value, email.value);
      var options = { 
        name: uid_name,
        expireseconds: expireseconds,
      }
      ONCE("pgp-created-uid", function (res) {
        notify.error(res.msg);
        self.update(res.key);
      });
      EMIT("pgp-create-uid", {keyid: self.key.id, options: options});
    } catch(e) {
      notify.error(e.toString());
    }
  }
}

Keyview.prototype.show_delete = function() {
  var self = this;
  var delete_ele = this.box.ele.querySelector("a[name='key-delete']");
  delete_ele.addEventListener("click", function(evt) {
    var confirm_msg = getStr("confirm_delete",
                        getStr(self.key.secret ? "secretkey":"publickey"), self.key.short_id);
    var rc = confirm(confirm_msg);
    if (rc) 
      EMIT("pgp-keyring-delete-keys", [self.key.id]);
  });
}

Keyview.prototype.show_export_sec = function() {
  var tab = this.tabs.get("key-secexport");
  var self = this;
  var pubexport = this.box.ele.querySelector("a[name='key-secexport']");
  pubexport.addEventListener("click", function(evt) {
    ONCE("pgp-secexported", function(res) {
      tab.ele.querySelector("pre").innerHTML = res.armored_key;
    });
    EMIT("pgp-secexport", {keyid: self.key.id});
  });
  var tofile = tab.ele.querySelector("button[name='tofile']");
  tofile.addEventListener("click", function(evt) {
    ONCE("pgp-exportedto", function(res) {
      tab.message(res.msg);
    });
    EMIT("pgp-secexportto", {keyid: self.key.id, to:"tofile"});
  });
  var toclipboard = tab.ele.querySelector("button[name='toclipboard']");
  toclipboard.addEventListener("click", function(evt) {
    ONCE("pgp-exportedto", function(res) {
      tab.message(res.msg);
    });
    EMIT("pgp-secexportto", {keyid: self.key.id, to:"toclipboard"});
  });
}

Keyview.prototype.show_export_pub = function() {
  var tab = this.tabs.get("key-pubexport");
  var self = this;
  var pubexport = this.box.ele.querySelector("a[name='key-pubexport']");
  pubexport.addEventListener("click", function(evt) {
    ONCE("pgp-pubexported", function(res) {
      self.box.ele.querySelector("pre").innerHTML = res.armored_key;
    });
    EMIT("pgp-pubexport", {keyids: [self.key.id]});
  });
  var tofile = this.box.ele.querySelector("button[name='tofile']");
  tofile.addEventListener("click", function(evt) {
    ONCE("pgp-exportedto", function(res) {
      tab.message(res.msg);
    });
    EMIT("pgp-export", {keyids: [self.key.id], to:"tofile"});
  });
  var toclipboard = this.box.ele.querySelector("button[name='toclipboard']");
  toclipboard.addEventListener("click", function(evt) {
    ONCE("pgp-exportedto", function(res) {
      tab.message(res.msg);
    });
    EMIT("pgp-export", {keyids: [self.key.id], to:"toclipboard"});
  });
  var tokeyserver = this.box.ele.querySelector("button[name='tokeyserver']");
  tokeyserver.addEventListener("click", function(evt) {
    ONCE("pgp-exportedto", function(res) {
      tab.message(res.msg);
    });
    EMIT("pgp-export", {keyids: [self.key.id], to:"tokeyserver"});
  });
}

Keyview.prototype.show_revocation = function() {
  var self = this;
  var tab = this.tabs.get("key-revoke");
  if (tab.ele==null) return;
  var inputs = tab.ele.querySelectorAll("input");
  for (var i=0;i<inputs.length;i++) {
    inputs[i].onkeypress = function(evt) {
      if (evt.keyCode == 13) {
        revoke_button.onclick();
      }
    }
  }
  var revoke_button = tab.ele.querySelector(".key_revoke_button");
  revoke_button.onclick = function(e) {
    var reason = tab.ele.querySelector(".revocation-reason").value;
    var comment = tab.ele.querySelector(".revocation-comment").value;
    ONCE("pgp-revoked-key", function (res) {
      self.update(res.key);
      notify.error(res.msg);
    });
    EMIT("pgp-revoke-key", {keyid:self.key.id, reason:reason, comment:comment});
  }
}

Keyview.prototype.serialize = function() {
  var ret = this.key;
  ret.str = this.str;
  ret.editable = this.editable;
  ret.selectable = this.selectable;
  ret.debug = DEBUG;
  return ret;
}

Keyview.prototype.show_debug = function() {
  var debug = this.box.ele.querySelector("[name='debug']");
  debug.textContent = JSON.stringify(this.key, null, '\t');
}

Keyview.prototype.remove_uid = function(uid_num) { 
  var uid_ele = this.uid_views[uid_num].target;
  uid_ele.parentNode.removeChild(uid_ele);
  this.uid_views.splice(uid_num, 1);
  for (var i=0; i<this.uid_views.length; i++) {
    this.uid_views[i].uid_num = i;
  }
}

Keyview.prototype.remove_subkey = function(subkey_num) { 
  var subkey_ele = this.subkey_views[subkey_num].target;
  subkey_ele.parentNode.removeChild(subkey_ele);
  this.subkey_views.splice(subkey_num, 1);
  for (var i=0; i<this.subkey_views.length; i++) {
    this.subkey_views[i].subkey_num = i;
  }
}

Keyview.prototype.update = function(key) { 
  try {
    if (key) {
      this.key = key;
    }
    this.box.updateTitle(this.makeTitle());
    this.uid_views = [];
    this.subkey_views = [];
    var self = this;

    Keyview.template.update(this.box.content_ele, this.serialize());

    this.uids = this.box.ele.querySelector("ul[name='key_uids']");
    var last = null;
    for (var i=0;i<this.key.uids.length;i++) {
      var newli = document.createElement("li");
      this.uids.appendChild(newli);
      var uid = this.key.uids[i];
      var uid_view = new Useridview(newli, this.key, i, this.editable, this.str);
      this.uid_views.push(uid_view.init());
      addClass(uid_view.box.icon_ele, "uid") 
      last = uid_view;
    }
    this.subkeys = this.box.ele.querySelector("ul[name='key_subkeys']");
    for (var i=0;i<this.key.subkeys.length;i++) {
      var newli = document.createElement("li");
      this.subkeys.appendChild(newli); 
      var subkeyview = new Subkeyview(newli, this.key, i, this.editable, this.str);
      this.subkey_views.push(subkeyview.init());
      addClass(subkeyview.box.icon_ele, "subkey") 
      last = subkeyview;
    } 
    var tabsele = this.box.ele.querySelector(".key_menu");
    this.tabs = Tabs.create(tabsele);

    this.show_export_pub();
    if (this.editable) {
      this.show_delete();
    }
    if (this.key.secret) {
      this.show_export_sec();
      this.show_revocation();
      this.show_createsub();
      this.show_createuid();
    }
    if (DEBUG)
      this.show_debug();
    return this;
  } catch(err) { 
    log_error(err);
  }
}

function Subkeyview(target, key, subkey_num, editable, str) {
  this.target = target;
  this.key = key;
  this.subkey_num = subkey_num;
  this.editable = editable || false;
  this.str = str;
  this.subkey = key.subkeys[subkey_num];
  this.tabs = null;
  this.box = null;
}

Subkeyview.template = new EJS({
  url: './templates/key_subkey_template.ejs',
  type: '['
});

Subkeyview.prototype.init = function() {
  var self = this;
  this.box = Box.create(this.target, "subkey-" + this.subkey.id, this.makeTitle(), "", {show_close_button:false});
  this.update();
  return this;
}

Subkeyview.prototype.makeTitle = function() {
  this.title = "<span class=\"keypub\">sub </span>";
  this.title += "<span class=\"keyid\">" + this.subkey.short_id + "</span>";
  if (this.subkey.revoked) 
    this.title += " <span class=\"invalid_key\">" + getStr("revoked") + "</span>";
  else if (!this.subkey.valid)
    this.title += " <span class=\"invalid_key\">" + getStr("invalid") + "</span>";
  return this.title;
}

Subkeyview.prototype.show_delete = function() {
  var self = this;
  var delete_ele = this.target.querySelector("a[name='subkey-delete']");
  delete_ele.addEventListener("click", function(evt) {
    var confirm_msg = getStr("confirm_delete",
                        getStr(self.key.secret ? "secretsubkey":"publicsubkey"), self.subkey.short_id);
    var rc = confirm(confirm_msg);
    if (rc) 
      EMIT("pgp-keyring-delete-uid", self.subkey.id);
  });
}

Subkeyview.prototype.show_revocation = function() {
  var tab = this.tabs.get("subkey-revoke");
  var revoke_button = tab.ele.querySelector("[name='sub_revoke_button']");
  var self = this;
  revoke_button.onclick = function(evt) {
    ONCE("pgp-revoked-subkey", function (res) {
      self.update(res.subkey);
      notify.error(res.msg);
    });
    var req = {
      subkeyid: self.subkey.id,
      reason: tab.ele.querySelector(".revocation-reason").value,
      comment: tab.ele.querySelector(".revocation-comment").value,
    }
    EMIT("pgp-revoke-subkey", req)
  }
}

Subkeyview.prototype.serialize = function() {
  var ret = this.subkey;
  ret.editable = this.editable;
  ret.revoked = this.subkey.revoked || this.key.revoked;
  ret.str = this.str;
  return ret;
};

Subkeyview.prototype.update = function(subkey, subkey_num) {
  if (subkey) {
    this.subkey = subkey;
    this.subkey_num = subkey_num || this.subkey_num;
    this.box.updateTitle(this.makeTitle());
  }
  Subkeyview.template.update(this.box.content_ele, this.serialize());
  var tabsele = this.target.querySelector(".subkey_menu");
  this.tabs = Tabs.create(tabsele) 
  if (this.editable) {
    this.show_revocation();
    this.show_delete();
  }
}

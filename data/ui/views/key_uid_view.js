function Useridview(target, key, uid_num, editable, str) {
  this.target = target;
  this.key = key;
  this.uid_num = uid_num;
  this.editable = editable || false;
  this.str = str;

  this.uid = key.uids[uid_num];
  this.key_id = key.key_id;
  this.tabs = null;
  this.sig_views = [];
}

Useridview.template = new EJS({
  url: './templates/key_uid_template.ejs',
  type: '['
});

Useridview.prototype.init = function() {
  var self = this;
  this.box = Box.create(this.target, this.key_id + "-uid-" + this.uid_num, 
                        this.makeTitle(), "", {show_close_button:false});
  this.update();
  return this;
}

Useridview.prototype.makeTitle = function() {
  var keytype = this.key.type ? "pub" : "sec";
  this.title = "<span class=\"key"+keytype+"\">uid </span>";
  if (this.uid.revoked) 
    this.title += "  <span class=\"invalid_key\">" + getStr("revoked") + "</span>";
  else if (!this.uid.valid)
    this.title += "  <span class=\"invalid_key\">" + getStr("invalid") + "</span>";

  this.title += "  <span class=\"uidname\">" + escapeHTML(this.uid.name) + "</span>";
  return this.title;
}

Useridview.prototype.show_revocation = function() {
  var tab = this.tabs.get("uid-revoke");
  var revoke_button = tab.ele.querySelector("[name='uid_revoke_button']");
  var self = this;
  revoke_button.onclick = function(evt) {
    ONCE("pgp-revoked-uid", function (res) {
      self.update(res.uid);
      notify.error(res.msg);
    });
    var req = {
      keyid: self.key.id,
      uid_index: self.uid_num,
      reason: tab.ele.querySelector(".revocation-reason").value,
      comment: tab.ele.querySelector(".revocation-comment").value,
    }
    EMIT("pgp-revoke-uid", req)
  }
}

Useridview.prototype.serialize = function() {
  var obj = this.uid;
  obj.uid_num = this.uid_num;
  obj.description = "";
  obj.keyid = this.key_id;
  obj.secret = this.key.secret;
  obj.revoked = this.uid.revoked || this.key.revoked;
  obj.editable = this.editable;
  obj.str = this.str;
  return obj;
}

Useridview.prototype.show_sign = function() {
  var buttons = this.target.querySelectorAll("[name='uid-sign']");
  var self = this;
  for (var i=0; i< buttons.length; i++)
    buttons[i].onclick = function() {
      EMIT("pgp-sign-uid", self.key.id, self.uid.name);
    }
}

Useridview.prototype.show_delete = function() {
  var self = this;
  var delete_ele = this.target.querySelector("a[name='uid-delete']");
  delete_ele.addEventListener("click", function(evt) {
    var confirm_msg = getStr("confirm_delete", 
                        getStr("userid"), self.uid.name);
    var rc = confirm(confirm_msg);
    if (rc) 
      EMIT("pgp-keyring-delete-uid", self.key.id, self.uid_num);
  });
}

Useridview.prototype.show_edit = function() {
  var self = this;
  var thistab = this.target.querySelector("[name='uid-edit-content']");
  var update_ele = thistab.querySelector("[name='update-uid']");
  var expiredate = thistab.querySelector("#expiredate");
  var expire_format = thistab.querySelector("#expiredateformat");
  expire_format.onchange = function(evt) { 
    expiredate.disabled = (evt.target.value == "never");
  }
  update_ele.addEventListener("click",
    function(evt) {
      if (!expiredateValidation(expire_format.value, expiredate)) return;
      var expireseconds = getExpireSeconds(expire_format.value, expiredate.value)
      ONCE("pgp-updated-uid-selfsig", function(res) {
        if (res.rc) {
          notify.error(res.msg);
          return;
        }
        self.update(res.uid);
      });
      EMIT("pgp-update-uid-selfsig", {keyid: self.key.id, 
        uid_num: self.uid_num, expireseconds: expireseconds});
    }
  );
}

Useridview.prototype.update = function(uid) {
  try {
    if (uid) {
      this.uid = uid;
      this.box.updateTitle(this.makeTitle());
    }
    Useridview.template.update(this.box.content_ele, this.serialize());
    var tabsele = this.target.querySelector(".uid_menu");
    var sigs = this.uid.sigs;

    var newli = document.createElement("li");
    this.box.content_ele.appendChild(newli);
    if (sigs.length) {
      var sigsbox = Box.create(newli, 'sigs', getStr("certsigs", sigs.length), "", {show_close_button:false});

      for (var i=0;i<sigs.length;i++) {
        var uidview = Useridsigview.create(sigsbox.content_ele, this.key, this.uid_num, i);
        this.sig_views.push(uidview);
      }
    }
    if (this.editable) {
      this.tabs = Tabs.create(tabsele) 
      this.show_edit();
      this.show_revocation();
      this.show_sign();
      this.show_delete();
    }
  } catch(err) {
    log_error(err);
  }
}

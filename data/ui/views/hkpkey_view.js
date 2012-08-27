function Hkpkeyview(key, target_ele) {
  this.key = key;
  this.target = target_ele;
  this.title = "";
  this.uid_views = [];
  this.subkey_views = [];
  this.tabs = null;
  this.editable = false;
  this.hkpkeyele = null;
}

Hkpkeyview.template = new EJS({
  url: './templates/hkpkey_template.ejs',
  type: '['
});

Hkpkeyview.create = function(key, target_ele, editable) {
  return new Hkpkeyview(key, target_ele).init();
}

Hkpkeyview.prototype.init = function() {
  var self = this;
  this.update();
  this.hkpkeyele = this.target.querySelector(".hkpkey");
  this.checkele = this.target.querySelector("[name='keyserver-select']");
  this.hkpkeyele.onclick = function() {
    self.checkele.checked = !self.checkele.checked;
  }

  return this;
}

Hkpkeyview.prototype.makeTitle = function(notescaped) {
  this.title = "";
  this.title += "<span class=\"keyid\">" + this.key.short_id + "</span>";
  if (this.key.revoked) 
    this.title += "  <span class=\"invalid_key\">" + getStr("revoked") + "</span>";
  else if (!this.key.valid)
    this.title += "  <span class=\"invalid_key\">" + getStr("invalid") + "</span>";

  if (this.key.uids.length) 
    this.title += "  <span class=\"keytitle\">" + escapeHTML(this.key.uids[0].uid) + "</span>";
  return this.title;
}

Hkpkeyview.prototype.serialize = function() {
  var ret = this.key;
  ret.str = strings;
  ret.title = this.makeTitle();
  for (var i=0;i<this.key.uids.length;i++) 
    ret.uids[i].uid = escapeHTML(this.key.uids[i].uid);
  return ret;
}


Hkpkeyview.prototype.update = function(key) { 
  if (key) 
    this.key = key;
  var self = this;
  Hkpkeyview.template.update(this.target, this.serialize());
  return this;
}


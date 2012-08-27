function Useridsigview(target, key, uid_num, sig_num) {
  this.target = target;
  this.key = key;
  this.uid = key.uids[uid_num];
  this.sig = key.uids[uid_num].sigs[sig_num];
  this.key_id = key.key_id;
  this.uid_num = uid_num;
  this.sig_num = sig_num;
  this.tabs = null;
  this.missing = true;
  this.missing_str = "";
}

Useridsigview.template = new EJS({
  url: './templates/key_uidsig_template.ejs',
  type: '['
});

Useridsigview.create = function(target, key, uid_num, sig_num) {
  var sigview = new Useridsigview(target, key, uid_num, sig_num);
  var eleid = key.id + "-uid-" + uid_num + "-sig-" + sig_num;
  sigview.newli = document.createElement("li");
  target.appendChild(sigview.newli);
  sigview.update();
  return sigview;
}

Useridsigview.prototype.makeTitle = function() {
  var keyele = ELE("key-" + this.sig.id);
  if (keyele) {
    this.missing = false;
    return keyele.querySelector('.title').innerHTML;
  } else {
    this.missing = true;
    return "" + escapeHTML(this.sig.id);
  }
}

Useridsigview.prototype.serialize = function() {
  var ret = this.sig;
  ret.title = this.makeTitle();
  ret.str = strings;
  ret.missing = this.missing;
  return ret;
}

var search_ts = [];
Useridsigview.prototype.update = function(uid) {
  var self = this;
  if (uid)
    this.uid = uid;
  Useridsigview.template.update(this.newli, this.serialize());
  var dlele = this.newli.querySelector(".download");
  if (dlele)
    dlele.onclick = function() {
      var text = self.sig.id;
      search_ts = Date.now();
      ONCE("pgp-keyblock-parsed", function( ) {
        Useridsigview.template.update(self.newli, self.serialize());
      });
      EMIT("pgp-key-parse", "keyserver", search_ts, [text]); 
    }
}

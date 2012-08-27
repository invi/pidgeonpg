function Keylistview() {
  this.list_ele = undefined;
  this.keyring = undefined;
  this.sorted_keys = undefined;
  this.onselect = [];
  this.list = {};
}

Keylistview.create = function(target_id, keyring) {
  var list_ele = ELE(target_id);
  var keylistview = new Keylistview(list_ele, keyring);
  keylistview.list_ele = list_ele;
  keylistview.keyring = keyring;
  keylistview.sorted_keys = keyring.allkeys;
  keylistview.init();
  return keylistview;
}

Keylistview.prototype.clear = function(key) {
  this.list_ele.innerHTML = "";
}

Keylistview.prototype.add = function(key) {
  try {
    var li_ele = document.createElement("li");
    var input = document.createElement("input");
    input.type = "checkbox";
    input.name = "select-" + key.id;
    input.setAttribute("style", "float:left");
    this.list[key.id] = Keyview.create(key, this.list_ele, true, true, false);
    var self = this;
    this.list[key.id].box.check_ele.addEventListener("change", function() {
      try {
        self.trigger("onselect"); 
      } catch(err) {
        log_error(err);
      }
      return false;
    });
  } catch(err) {
    log_error(err);
  }
}

Keylistview.prototype.trigger = function(evt_type) {
  var cbs = this[evt_type];
  for (var i=0; i<cbs.length; i++) {
    cbs[i](this);
  }
}

Keylistview.prototype.selectAll = function() {
  for (var i in this.list) {
    if (this.list[i].box.ele.style.display != "none")
      this.list[i].setSelected(true);
  }
}

Keylistview.prototype.selectNone = function() {
  for (var i in this.list) { 
    if (this.list[i].box.ele.style.display != "none")
      this.list[i].setSelected(false);
  }
}

Keylistview.prototype.selectInvert = function() {
  for (var i in this.list)  
    if (this.list[i].box.ele.style.display != "none")
      this.list[i].setSelected(!this.list[i].box.check_ele.checked);
}

Keylistview.prototype.orderBy = function(type) {
  switch(type) {
    case 'name':
    this.clear();
    function compare(a,b) {
      if (a.uids[0].name < b.uids[0].name)
         return -1;
      if (a.uids[0].name > b.uids[0].name)
        return 1;
      return 0;
    }
    this.sorted_keys.sort(compare);
    this.init();
    break;
    default:
    break;
  }
}

Keylistview.prototype.resort = function() {
  for (var i=0; i<this.keyring.allkeys.length; i++) {
    if (i < this.sorted_keys.length) {
      var ele = this.list_ele.querySelector("#key-" + this.sorted_keys[i].id) 
      var fchild = this.list_ele.childNodes[i];
      this.list_ele.insertBefore(ele, fchild);
      ele.style.display = "";
    } else {
      var ele = this.list_ele.childNodes[i];
      ele.style.display = "none";
    }
  }
}

Keylistview.prototype.filter = function(name) {
    function compare(a,b) {
      if (a.uids[0].name < b.uids[0].name)
         return -1;
      if (a.uids[0].name > b.uids[0].name)
        return 1;
      return 0;
    }
    var keys = this.keyring.allkeys;
    var ret = [];
    try {
      for (var i=0; i<keys.length; i++) {
        if (keys[i].uids[0].name.toUpperCase().indexOf(name.toUpperCase()) > -1 ||
            keys[i].id.toUpperCase().indexOf(name.toUpperCase()) > -1) {
            ret.push(keys[i]);
        }
      }
    } catch(err) { log_error(err); };
    this.sorted_keys = ret;
  this.resort();
}

Keylistview.prototype.getSelected = function() {
  var ret = [];
  for (var i in this.list) 
    if (this.list[i].box.check_ele.checked == true) {
      ret.push(this.list[i]);
    }
  return ret;
}

Keylistview.prototype.getSelectedKeyIDs = function() {
  var ret = [];
  for (var i in this.list) 
    if (this.list[i].box.check_ele.checked == true) {
      ret.push(i);
    }
  return ret;
}

Keylistview.prototype.getNumKeys = function() {
  var numkeys = 0;
  for (var i in this.list) 
    numkeys++;
  return numkeys;
}

Keylistview.prototype.subscribe = function() {
  var self = this;
  ON("pgp-key-imported", function(res) {
    if (res.key.id in self.list) 
      self.update(res.key) 
    else
      self.add(res.key);
  });
  ON("pgp-keyring-deleted-keys", function(res) {
    for (var i=0; i<res.deleted_keys.length; i++) 
      self.remove(res.deleted_keys[i]);
  });
  ON("pgp-keyring-deleted-uid", function(res) {
    self.list[res.keyid].remove_uid(res.uid_num);
  });
  ON("pgp-keyring-deleted-subkey", function(res) {
    self.list[res.keyid].remove_subkey(res.subkey_num);
  });
}

Keylistview.prototype.remove = function(keyid) {
  var item = ELE("key-" + keyid);
  item.parentNode.removeChild(item);
}

Keylistview.prototype.init= function() {
  var kl = this.sorted_keys;
  for (var i=0; i<kl.length; i++) 
    this.add(kl[i]);
  this.subscribe();
}

Keylistview.prototype.addEventListener = function(evt_type, func) {
  switch (evt_type) {
    case 'onselect':
      this.onselect.push(func);
      break;
    default:
      throw "Event type " + evt_type + " not exists";
  }
}

Keylistview.prototype.update = function(key) {
  var view = this.list[key.id];
  view.update(key);
}

Keylistview.prototype.update_uid = function(key, uid, uid_num) {
  var view = this.list[key.id].uid_views[uid_num];
  view.update(uid);
}

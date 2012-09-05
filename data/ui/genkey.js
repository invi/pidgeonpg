var genkey = { 
  ele: null, 
  boxes: null,
  box: null,
  name_ele: null,
  email_ele: null,
  comment_ele: null,
  expiredate_ele: null,
  results_ele: null,
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  clear: function() {
    var fields = [this.name_ele, this.email_ele, this.comment_ele, this.expiredate_ele];
    for (var i=0; i<fields.length; i++) {
      fields[i].value = "";
    }
  },
  load: function() {
    this.ele = document.getElementById("dialog-genkey"); 
    var ele_genkey_key_type = this.Q("#pgp-genkey-key-type");
    var ele_genkey_key_length = this.Q("#pgp-genkey-key-length");
    var ele_genkey_expiredateformat = this.Q("#pgp-genkey-expiredateformat");
    var ele_genkey_expiredate = this.Q("#expiredate");
    var ele_genkey_button = this.Q("#pgp-genkey-button");
    this.email_ele = this.Q("#email");
    this.name_ele = this.Q("#name");
    this.comment_ele = this.Q("#comment");
    this.expiredate_ele = this.Q("#expiredate");

    this.results_ele = this.Q(".results");
    this.boxes = new Boxes(this.results_ele);
    
    var ele_genkey_close = this.Q(".closeicon");
    ele_genkey_close.onclick = function() { 
      Dialogs.close_dialog() 
    };
    
    ele_genkey_expiredate.disabled  = true;
    
    ele_genkey_key_type.onchange = function (e) {
      const options = { 
        "RSA": { lengths:["1024", "2048", "4096"], default_length:"2048"},
        "DSA": { lengths: ["1024"], default_length:"1024"}
      };
      const key_type =  ele_genkey_key_type.value
      ele_genkey_key_length.innerHTML = "";
      for (var i=0; i < options[key_type].lengths.length; i++) {
          var key_length = options[key_type].lengths[i];
          var opt = document.createElement("option");
          opt.value = key_length;
          opt.textContent = key_length;
          if (key_length == options[key_type].default_length)
              opt.selected="selected";
          ele_genkey_key_length.appendChild(opt);
      }
    }
    
    ele_genkey_expiredateformat.onchange = function (e) {
      ele_genkey_expiredate.disabled = e.target.value == "never";
    }
    
    var self = this;
    ele_genkey_button.onclick = function() { 
      try {
        var expire_format = self.Q("#pgp-genkey-expiredateformat").value;
        var keyType = ele_genkey_key_type.value == "RSA"? ALGO.RSA: ALGO.DSA;
        var subkeyType = ele_genkey_key_type.value == "RSA"? ALGO.RSA: ALGO.ELGAMAL_E;
    
        var uid_name = buildUserId(self.name_ele.value, self.comment_ele.value, self.email_ele.value);
        var valid_email = emailValidation(self.email_ele)
        var valid_expiredate = expiredateValidation(expire_format, self.expiredate_ele);
        if (valid_email && valid_expiredate) {
          var title = getStr("generating");
          var box = self.boxes.create(title);
          var pars = {
            seqts: box.ts,
            name: uid_name,
            keyType: keyType,
            subkeyType: subkeyType,
            keypairBits: parseInt(ele_genkey_key_length.value),
            expireseconds: getExpireSeconds(expire_format, self.expiredate_ele.value),
          };
          EMIT("pgp-key-generate", pars);
          self.mode_processing();
        }
      } catch(err) {
        log_error(err);
      }
    }
  },
  mode_finished: function() {
    var self = this;
    this.box.addEventListener("onclose", function() {
      self.results_ele.innerHTML = "";
      self.mode_initial();
    });
  },
  mode_initial: function() {
    genkey.clear();
    this.Q(".form").style.display = "";
    this.results_ele.style.display = "none";
  },
  mode_processing: function() {
    this.Q(".form").style.display = "none";
    this.results_ele.style.display = "";
    var self = this;
    ONCE("pgp-key-generated", function(res) {
      try {
        var title = res.rc ? getStr("generate_error") : getStr("generated", res.key.id);
        self.box = self.boxes.get(res.ts);
        self.box.stopProgress();
        self.box.updateTitle(title);
    
        if (res.rc == 0) {
          var keyview = Keyview.create(res.key, self.box.content_ele, false, false, true);
          keyview.update();
        }
      } catch(err) {
        log_error(err);
      }
      self.mode_finished();
    });
  },
}

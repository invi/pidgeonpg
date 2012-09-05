var encrypt = {
  ele: null, 
  boxes: null,
  box: null,
  recipients_ele: null,
  results_ele: null,
  encrypt_button_ele: null,
  issuer_ele: null,
  sign_check_ele: null,
  text_box_ele : null,
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  clear:  function() {
    this.text_box_ele.value = "";
    this.recipients_ele.selectedIndex = 0;
    this.sign_check_ele.checked = false;
    this.issuer_ele.disabled = true;
    this.encrypt_button_ele.disabled = true;
  },
  load: function() {
    this.ele = document.getElementById("dialog-encrypt");
    this.recipients_ele = this.Q("#pgp-encrypt-recipients-list");
    this.results_ele = this.Q(".results");
    this.encrypt_button_ele = this.Q("#pgp-encrypt-button")
    this.issuer_ele = this.Q("#pgp-enc-and-sign-recipients-list");
    this.sign_check_ele = this.Q("#pgp-sign-check");
    this.text_box_ele = this.Q("#pgp-encrypt-text");

    var boxes = new Boxes(this.results_ele);
    this.issuer_ele.disabled = true;
    this.encrypt_button_ele.disabled = true;

    
    var self = this;
    function updateEncryptButton() { 
      self.encrypt_button_ele.disabled = self.text_box_ele.value.length == 0 
        || self.recipients_ele.value == "";
    }
    
    this.text_box_ele.oninput = updateEncryptButton;
    this.recipients_ele.onchange= updateEncryptButton;
    Keyring.subscribeSelect(this.recipients_ele, "encryptionkeys")
    Keyring.subscribeSelect(this.issuer_ele, "signingkeys")
    
    this.sign_check_ele.onchange = function(evt) {
      var select = self.issuer_ele;
      select.disabled = !evt.target.checked;
    };
    
    this.encrypt_button_ele.onclick = function(evt) {
      try {
        var selected = getSelected(self.recipients_ele);
        var enc_keyid = selected.value; 
        var sign_keyid = []; 
        var title = "";
        var enc_link = Keyring.format_keylink(enc_keyid);
        var sign = self.sign_check_ele.checked;
        if (sign) {
          var skey_value = self.issuer_ele.value;
          sign_keyid = skey_value != "" ? [skey_value] : [];
          var sign_link = Keyring.format_keylink(sign_keyid);
          title = getStr("encryptingandsigningto", enc_link, sign_link);
        } else {
          title = getStr("encryptingto", enc_link);
        }
        var msg = self.text_box_ele.value;
        self.box = boxes.create(title, {msg: msg});
    
        EMIT("pgp-msg-encrypt", {
          ts: self.box.ts,
          msg: msg,
          enc_keyid: enc_keyid,
          sign_keyid: sign_keyid
        });
        self.mode_processing();
      } catch(err) {
        log_error(err);
      }
    }
    
    ON("pgp-msg-encrypted", function(res) { 
      var box = boxes.get(res.ts);
      var title = "";
      var enc_link = Keyring.format_keylink(res.enc_keyid);
      var sign_link = res.sign_keyid ? Keyring.format_keylink(res.sign_keyid) : "";
      if (!res.rc) {
        if (res.sign_keyid) 
          title += getStr("encryptedandsignedto", enc_link, sign_link);
        else  
          title += getStr("encryptedto", enc_link);
        var details = "<pre>" + res.msg + "</pre><br />" + 
                      "<b>Original message:</b><pre>" + box.msg + "</pre>";
        createSaveButtons(box.content_ele, res.msg, details);
      } else {
        title = res.sign_keyid ? getStr("error_encryptingandsigningto", enc_link, sign_link)
                               : getStr("error_encryptingto", enc_link);
        box.content_ele.textContent = res.msg;
      }
      box.stopProgress();
      box.updateTitle(title);
      self.mode_finished();
    });
  },
  mode_finished: function() {
    var self = this;
    this.box.addEventListener("onclose", function() {
      self.results_ele.innerHTML = "";
      self.mode_initial();
    });
  },
  mode_initial: function() {
    this.clear();
    this.Q(".form").style.display = "";
    this.results_ele.style.display = "none";
  },
  mode_processing: function() {
    this.Q(".form").style.display = "none";
    this.results_ele.style.display = "";
  }
}

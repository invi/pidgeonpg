var decrypt = {
  ele: null, 
  boxes: null,
  box: null,
  results_ele: null,
  input_ele: null,
  results_ele: null,
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  clear: function() {
    this.input.value = "";
    this.button.disabled = true;
  },
  load: function() {
    this.ele = document.getElementById("dialog-decrypt");
    this.input_ele = this.Q("#pgp-decrypt-input");
    this.button_ele = this.Q("#pgp-decrypt-button");
    this.results_ele = this.Q(".results");
    var boxes = new Boxes(this.results_ele);
    
    this.button_ele.disabled = true;
    var self = this;
    
    this.input_ele.oninput = function() {
      self.button_ele.disabled = self.input_ele.value.length == 0;
    }
    
    this.button_ele.onclick = function() {
      try {
        var msg = self.input_ele.value;
        var title = getStr("decrypting");
        self.box = boxes.create(title, {msg: msg});
        EMIT("pgp-msg-decrypt", {ts: self.box.ts, msg: self.box.msg});
        self.mode_processing();
      } catch(err) {
        log_error(err);
      }
    }
    
    ON("pgp-msg-decrypted", function(res) {
      try {
        var title = getStr("decrypted", Keyring.format_keylink(res.enc_keyid));
        switch (res.rc) {
          case -1: //error
            title = getStr("error_decrypting", res.ts);
            break;
          case 0: //decrypted not signed message
            //title += "<br />" + getStr("decrypted_notsigned");
            break;
          case 1: //decrypted and valid signature
            title += "<br />" + getStr("decrypted_signed", Keyring.format_keylink(res.sign_keyid));
            break;
          case 2: //decrypted but signed key missing
            title += "<br />" + getStr("decrypted_missingsigkey", res.sign_keyid);
            break;
          case 3: //decrypted but invalid signature
            title += "<br />" + getStr("decrypted_notvalid", res.sign_keyid);
            break;
        }
        var box = boxes.get(res.ts);
        if (res.rc >= 0) 
          createSaveButtons(box.content_ele, res.msg, "<pre>" + res.msg + "</pre>");
        else
          box.content_ele.textContent = res.msg;
        box.stopProgress();
        box.updateTitle(title);
        self.mode_finished();
      } catch(err) {
        log_error(err);
      }
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

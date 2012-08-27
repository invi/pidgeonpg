var sign = {
  ele: null,
  boxes: null,
  box: null,
  results_ele: null,
  input_ele: null,
  issuer_ele: null,
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  clear: function clearForm() {
    this.button_ele.disabled = true;
    this.input_ele.value = "";  
    this.input_ele.focus();
  },
  load: function() {
    this.ele = document.getElementById("dialog-sign");
    this.button_ele = this.Q("#pgp-sign-button");
    this.input_ele = this.Q("#pgp-sign-input");
    this.issuer_ele = this.Q("#pgp-sign-recipients-list");
    this.results_ele = this.Q(".results");
    var boxes = new Boxes(this.results_ele);
    
    this.button_ele.disabled = true;
    Keyring.subscribeSelect(this.issuer_ele, "signingkeys");
    var self = this;
    
    function updateSignButton() { 
      self.button_ele.disabled = self.input_ele.value.length == 0 
        || self.issuer_ele.value == "";
    }
    
    this.input_ele.oninput = updateSignButton;
    this.issuer_ele.onchange= updateSignButton;
    
    this.button_ele.onclick = function() {
      try {
        var msg = self.input_ele.value;
        var keyid = self.issuer_ele.value;
        var title = getStr("signing", Keyring.format_keylink(keyid));
        self.box = boxes.create(title, {msg: msg});
        EMIT("pgp-msg-sign", {ts: self.box.ts, msg: msg, keyid: keyid});
        self.mode_processing();
      } catch(err) {
        log_error(err);
      }
    }
    
    ON("pgp-msg-signed", function(res) {
      var title;
      var box = boxes.get(res.ts);
      if (res.rc == 0) {
        var details = "<pre>" + res.msg + "</pre>" + 
                      "<b>Original Message:</b><pre>" +  box.msg + "</pre>";
        createSaveButtons(box.content_ele, res.msg, details);
        title = getStr("signed", Keyring.format_keylink(res.sig));
      } else {
        box.content_ele.innerHTML = res.msg;
        title = getStr("error_signing");
      }
      box.stopProgress();
      box.updateTitle(title);
      self.mode_finished();
    })
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

var verify = {
  ele: null,
  boxes: null,
  box: null,
  button_ele: null,
  results_ele: null,
  input_ele: null,
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  clear: function() {
    this.button_ele.disabled = true;
    this.input_ele.value = '';
    this.input_ele.focus();
  },
  load: function() {
    this.ele = document.getElementById("dialog-verify");
    this.results_ele = this.Q(".results");
    this.button_ele = this.Q("#pgp-verify-button");
    this.input_ele = this.Q("#pgp-verify-input");
    var boxes = new Boxes(this.results_ele);
    
    this.button_ele.disabled = true;
    var self = this;
    
    
    this.input_ele.oninput = function() {
      self.button_ele.disabled = self.input_ele.value.length == 0 
    }
    
    this.button_ele.onclick = function() {
      var msg = self.input_ele.value;
      self.box = boxes.create(getStr("verifying"), {msg: msg});
      EMIT("pgp-msg-verify", {msg:msg, ts: self.box.ts});
      self.mode_processing();
    }
    
    ON("pgp-msg-verified", function(res) {
      var title = "";
      if (res.rc==0) 
        if (res.valid) 
          title = getStr("verified", Keyring.format_keylink(res.issuerid));
        else 
          title = getStr("verified_notvalid", Keyring.format_keylink(res.issuerid));
      else if (res.rc==1) 
        title = getStr("verified_missingsigkey", res.issuerid);
      else 
        title = getStr("error_verifying");
      var box = boxes.get(res.ts);
      box.content_ele.innerHTML = escapeHTML("<div name='box-result'><pre>" + box.msg + "</pre></div>");
      box.stopProgress();
      box.updateTitle(title);
      self.mode_finished();
    });
  },
  mode_finished: function() {
    var self = this;
    this.box.addEventListener("onclose", function() {
      try {
        self.results_ele.innerHTML = "";
        self.mode_initial();
      } catch(err) {
        log_error(err);
      }
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

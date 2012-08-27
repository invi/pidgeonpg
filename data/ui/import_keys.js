var import_keys = {
  ele: null,
  boxes: null,
  box: null,
  results_ele: null,
  input_ele: null,
  button_ele: null,
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  clear: function() {
    this.results_ele.innerHTML = "";
    this.input_ele.value = "";
    this.input_ele.focus();
  },
  load: function() {
    this.ele = document.getElementById("dialog-import_keys");
    this.results_ele = this.Q(".results");
    this.input_ele = this.Q("#pgp-import-input");
    this.button_ele = this.Q("#pgp-import-button");
    var boxes = new Boxes(this.results_ele);
    var self = this;

    this.button_ele.addEventListener("click", function() {
      try {
        var box = boxes.createImport(getStr("importing"),null, true);
        self.box = box;
        EMIT("pgp-key-parse", "text", box.ts, null, self.input_ele.value);
        self.mode_processing();
      } catch(err) {
        log_error(err);
      }
    });
    
    ON("pgp-key-imported", function(res) {
      var box = boxes.get(res.ts)
      if (box) {
        box.show();
        box.updateTitle(res.msg + "<br />" + getStatsStr(box));
        var title = "";
        switch (res.key.ringstatus) {
          case PGP.KEYSTATUS.NEW:
            box.new_keys++;
            title += "NEW"
            break;
          case PGP.KEYSTATUS.CHANGED:
            box.updated_keys++;
            title += "UPDATED"
            break;
          case PGP.KEYSTATUS.UNCHANGED:
            box.unchanged_keys++;
            title += "UNCHANGED"
            break;
          default:
            title += "ERROR"
            box.error_keys++;
            break;
        }
        var ul = document.createElement("ul");
        box.content_ele.appendChild(ul);
        li = document.createElement("li");
        Keyview.create(res.key, li, false);
        ul.insertBefore(li, ul.firstChild);
      }
    });
    
    ON("pgp-keyblock-parsed", function(res) {
      var box = boxes.get(res.ts)
      if (box) {
        box.show();
        box.updateTitle(res.msg + "<br />" + getStatsStr(box));
        box.stopProgress();
        self.mode_finished();
      }
    });
  },
  mode_finished: function() {
    var self = this;
    self.box.addEventListener("onclose", function() {
      self.results_ele.innerHTML = "";
      self.mode_initial();
    });
  },
  mode_initial: function() {
    this.Q(".form").style.display = "";
    this.results_ele.style.display = "none";
    this.clear();
  },
  mode_processing: function() {
    this.Q(".form").style.display = "none";
    this.results_ele.style.display = "";
  }
}

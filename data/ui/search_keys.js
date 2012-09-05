var search_keys = {
  ele: null,
  box: null,
  input_ele: null,
  search_button_ele: null,
  import_button_ele: null,
  clear_button_ele: null,
  results_ele: null,
  search_results_ele: null,
  search_ts: null,
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  load: function() {
    var self = this;
    this.ele = document.getElementById("dialog-search_keys");
    this.search_button_ele = this.Q("#keyserver-search-button");
    this.input_ele = this.Q("#keyserver-search-input");
    this.result_box_ele = this.Q("#keyserver-search-result-box");
    this.results_ele = this.Q(".results");
    this.search_results_ele = this.Q(".search-results");
    this.import_button_ele = this.Q("#keyserver-import-button");
    this.clear_button_ele = this.Q("#keyserver-clear-button");
    var boxes = new Boxes(this.results_ele);

    this.clear_button_ele.onclick = function() {
      self.clear();
    }
    this.search_button_ele.onclick = function() {
      self.search();
    }
    ON("keyserver-search-result", function (res) {
      try {
        if (res.ts != self.search_ts) return;
        if (res.rc == -1) {
          self.search_results_ele.textContent = getStr("search_error", res.msg);
          return;
        }
        var keys = res.keys;
        function get_status(obj) {
          var obj_status = (obj.revoked ? 'revoked ' : '') +
            (obj.disabled ? 'disabled ' : '') + 
            (obj.expired ? 'expired' : '');
          obj_status = (obj_status == '') ?'valid':obj_status;
          return obj_status;
        }
        
        //TODO Convertir a plantilla
        self.search_results_ele.innerHTML = "";
        for (var i=0; i<keys.length; i++) {
          var li = document.createElement("li");
          var hkv = Hkpkeyview.create(keys[i], li);
          hkv.hkpkeyele.addEventListener("click", function() {
            var items = self.ele.querySelectorAll("[name='keyserver-select']");
            var found = false;
            for (var i=0;i<items.length;i++)
              if (items[i].checked) {
                found = true;
                break;
              }
            self.import_button_ele.disabled = !found;
          });
          self.search_results_ele.appendChild(li);
        }
        if (keys.length == 0) {
          log_debug("No keys were found in keyserver")
          self.set_status("No keys were found");
        }
      } catch(err) {
        log_error(err);
      }
    });
    this.import_button_ele.onclick = function() {
      try {
        var selected_keys = [];
        var items = self.ele.querySelectorAll("[name='keyserver-select']");
        for (var i=0; i < items.length; i++)
          if (items[i].checked)
            selected_keys.push(items[i].id.split('-')[1]);
        if (selected_keys.length > 0) {
          //ele_import_keyserver.style.display = "none";
          var box = boxes.create(getStr("importing"),null, false);
          self.box = box;
          box.new_keys = 0;
          box.updated_keys = 0;
          box.unchanged_keys = 0;
          box.error_keys = 0;
          EMIT("pgp-key-parse", "keyserver", box.ts, selected_keys); 
        }
        self.mode_processing();
      } catch (err) {
        log_error(err);
      }
    }
    ON("pgp-key-imported", function(res) {
      var box = boxes.get(res.ts)
      if (box) {
        const PGP = { "KEYSTATUS": { "NEW": 0, "CHANGED": 1, "UNCHANGED": 2 }};
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
  clear: function() {
    this.search_results_ele.innerHTML = '';
    this.results_ele.innerHTML = '';
    this.input_ele.value = '';
  },
  search: function() {
    try {
      var text = this.input_ele.value;
      if (text == '')
        return false;
      this.clear();
      this.search_ts = Date.now();
      EMIT("keyserver-search", {ts: this.search_ts, text: text});
      this.import_button_ele.disabled = true;
      this.set_status("Searching for keys");
    } catch(err) {
      log_error(err);
    }
  },
  set_status: function(str) {
    this.search_results_ele.textContent = str;
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
    this.Q("#keyserver-search-result-box").style.display = "";
  },
  mode_processing: function() {
    this.Q(".form").style.display = "none";
    this.Q("#keyserver-search-result-box").style.display = "none";
  }
}

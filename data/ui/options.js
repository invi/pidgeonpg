var options = {
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  load: function() {
    this.ele = document.getElementById("dialog-options");
    var cont = 0;
    const opt_elems= {
      keyserver: this.Q("#options-keyserver"),
      lang: this.Q("#options-lang-sel"),
      defaultkey: this.Q("#options-default-key"),
    }
    
    function option_changed(option, new_value) {
      notify.error("Option \"" + option + "\" changed to \"" +
            new_value + "\"", LOG_TYPE.SUCCESS);
    }
    
    opt_elems.lang.onchange = function(ele) { 
      var lang = ele.target.value;
      EMIT("pgp-options-set", "lang", lang);
    }
    
    opt_elems.keyserver.onchange = function(ele) {
      var keyserver = ele.target.value;
      if (keyserver != "")
        EMIT("pgp-options-set", "keyserver", keyserver);
    }
    
    opt_elems.defaultkey.onchange = function(ele) { //TODO: response mesage
      var key_id = ele.target.value;
      if (key_id != "")
        EMIT("pgp-options-set", "defaultkey", key_id); 
    }
    
    ON("pgp-option-set-error", function(res) {
      var msg = "Error setting " + res.key + " = " + res.value +
              ". (" + res.error + ")";
      notify.error(msg);
    });
    
    ON("pgp-options-got-all", function(options) {
      setDefaultOption(opt_elems.lang, options.lang);
      opt_elems.keyserver.value = options.keyserver;
    });
    
    ON("pgp-option-set-defaultkey", function(value) {
      option_changed("Default key", value);
    });
    
    ON("pgp-option-set-language", function(value) {
      //option_changed("Language", value);
      setDefaultOption(opt_elems.lang, value);
    });
    
    ON("pgp-option-set-keyserver", function(value) {
      option_changed("Key server", value);
    });
    
    //ON("pgp-options-fetched-keys", function(res) {
    //});
    
    ON("pgp-keyring-deleted-all-keys", function(num_keys) {
      var msg;
      if (num_keys > 0) 
        msg = getStr("deleted_allkeys");
      else 
        msg = getStr("deleted_empty");
    
      notify.error(msg);
    });
    
    //ON("pgp-key-imported", function() { 
    //    EMIT("pgp-options-fetch-keys");
    //});
    //
    //ON("pgp-keyring-deleted-keys", function() {
    //    EMIT("pgp-options-fetch-keys");
    //});
    
    EMIT("pgp-options-get-all");
    
    Keyring.subscribeSelect(opt_elems.defaultkey, "signingkeys")
  }
}

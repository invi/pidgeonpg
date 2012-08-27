function init_manager() {
  var ele_keyring_list = ELE("keyring-keys-list");
  var ele_keyring_keys = ELE("keyring-keys");
  var ele_keyring_export_button = ELE("expbut");
  var keylistview = Keylistview.create("keyring-keys", Keyring);
  
  function updateSelectButtons() {
    var num_selected = keylistview.getSelected().length;
    var num_total = keylistview.getNumKeys();
    Q(".selected-menu .numkeys").parentNode.style.visibility = (num_selected ? "": "hidden");
    Q(".selected-menu .numkeys").textContent= num_selected + " keys selected";

    Q(".keyring-select .all").style.display = (num_selected < num_total) ? "" : "none";
    Q(".keyring-select .none").style.display = (num_selected == 0) ? "none" : "";
    Q(".keyring-select .invert").style.display = (num_selected == 0 || num_selected == num_total) ? "none" : "";

  }
  Q(".keyring-select").onmousemove = function(evt) {
      if (!hasClass(Q(".keyring-select .sub-buttons"), "show"));
        addClass(Q(".keyring-select .sub-buttons"), "show");
  };
  Q(".selected-menu").onmousemove = function(evt) {
    if (Q(".selected-menu .numkeys").parentNode.style.visibility != "hidden") 
      if (!hasClass(Q(".selected-menu .sub-buttons"), "show"))
        addClass(Q(".selected-menu .sub-buttons"), "show");
  };
  Q(".import-menu").onmousemove = function(evt) {
    if (!hasClass(Q(".import-menu .sub-buttons"), "show"));
      addClass(Q(".import-menu .sub-buttons"), "show");
  };
  Q(".selected-menu .export").onclick = function(evt) {
    try {
      var sel_keyids = keylistview.getSelectedKeyIDs()
      Dialogs.open_dialog("export_selected");
      export_selected.export_keyids(sel_keyids);
    } catch(err) {
      log_error(err);
    }
  }
  Q(".selected-menu .encrypt").onclick = function(evt) {
    try {
      Dialogs.open_dialog("encrypt");
    } catch(err) {
      log_error(err);
    }
  }
  Q(".selected-menu .update").onclick = function(evt) {
    try {
      Dialogs.open_dialog("update");
    } catch(err) {
      log_error(err);
    }
  }
  Q(".selected-menu .remove").onclick = function(evt) {
    try {
      var num_selected = keylistview.getSelected().length;
      confirm(getStr("confirm_delete_selected", num_selected));
    } catch(err) {
      log_error(err);
    }
  }
  Q(".keyring-select .all").onclick = function(evt) {
    try {
      keylistview.selectAll();
      updateSelectButtons(); 
      removeClass(Q(".keyring-select .sub-buttons"), "show");
    } catch(err) {
      log_error(err);
    }
  }
  Q(".keyring-select .none").onclick = function(evt) {
    keylistview.selectNone();
    removeClass(Q(".keyring-select .sub-buttons"), "show");
    updateSelectButtons(); 
  }
  Q(".keyring-select .invert").onclick = function() {
    removeClass(Q(".keyring-select .sub-buttons"), "show");
    keylistview.selectInvert();
    updateSelectButtons(); 
  }
  
  Q("#filter").onkeyup = function(evt) {
    try {
      keylistview.filter(evt.target.value);
    } catch(err) {
      log_error(err);
    }
  }
  
  Q("#keyring-genkey").onclick = function(evt) {
    Dialogs.open_dialog("genkey", true);
  }
  Q("#menu-encrypt").onclick = function(evt) {
    Dialogs.open_dialog("encrypt", true);
  }
  Q("#menu-decrypt").onclick = function(evt) {
    Dialogs.open_dialog("decrypt", true);
  }
  Q("#menu-verify").onclick = function(evt) {
    Dialogs.open_dialog("verify", true);
  }
  Q("#menu-sign").onclick = function(evt) {
    Dialogs.open_dialog("sign", true);
  }
  Q(".search-keys .button").onclick = function(evt) {
    Dialogs.open_dialog("search_keys");
  }
  Q("#menu-options").onclick = function(evt) {
    Dialogs.open_dialog("options", true);
  }
  Q(".import-menu").onclick = function(evt) {
    Dialogs.open_dialog("import_keys", true);
    import_keys.mode_initial();
  }
  keylistview.addEventListener("onselect", function() {
    updateSelectButtons(); 
  });
  updateSelectButtons(); 
}

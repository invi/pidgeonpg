DEBUG = true;
var UI = {
  bgs: {},
  bgs_ele: {},
  prefix: "background-",
  strings: undefined,
  templates: {},
  init: function(options) {
    var dialogs = {"genkey":{dialog:false}, 
      "import_keys":{dialog:false}, 
      "search_keys":{dialog:true}, 
      "encrypt":{dialog:true}, 
      "decrypt":{dialog:true},
      "sign":{dialog:true}, 
      "manager":{dialog:true}, 
      "export_selected":{dialog:false}, 
      "options":{dialog:true}};
    this.strings = fetch_lang_file(options.lang);
    strings = this.strings;
    this.loadMain();
    var dlist = {};
    for (var i in dialogs) 
      if (dialogs[i].dialog)
        dlist[i] = dialogs[i];
    Dialogs.init(dlist, strings);
    Keyring.init(null, options.defaultkeyid, function() {
      UI.updateBackground();
    });
    ON("open-section", function(name) {
      if (name == "manager") {
        Dialogs.close_dialog(name);
      } else
        Dialogs.open_dialog(name);
    });
  },
  loadMain: function() {
    this.main_template = new EJS({
      url: './templates/main.ejs',
      type: '['
    });
    this.main_template.update(document.body, {str: this.strings});
  },
  load: function(name) {
    this.templates[name] = new EJS({
      url: './templates/' + name + '.ejs',
      type: '['
    });
    var bgs_ele = document.createElement("div");
    bgs_ele.id = this.prefix + name;
    bgs_ele.className = "background";
    this.bgs_ele[name] = bgs_ele;
    this.templates[name].update(bgs_ele, {str: this.strings});
    Q("#background").appendChild(bgs_ele);
    window["init_" + name]();
  },
  set_background: function(name) {
    if (!(name in this.bgs_ele)) 
      this.load(name);
  },
  updateBackground: function() {
//    if (Keyring.allkeys.length)
      this.set_background("manager");
 //   else
  //    this.set_background("welcome");
  }
}



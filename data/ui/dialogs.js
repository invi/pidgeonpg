var Dialogs = {
  dialogs: undefined,
  strings: undefined,
  dialogs_ele: {},
  title_ele: Q("title"),
  prefix: "dialog-",
  title: "PidgeonPG::",
  menu_ele: Q("#menu"),
  menu_items: {},
  templates: {},
  init: function(dialogs, strings) {
    this.dialogs = dialogs;
    this.strings = strings;
    Q("#container-background").onclick = function() {
      Dialogs.close_dialog();
    }
  },
  open_dialog: function(name, ontop) {
    addClass(Q("#container-background"), "show");
    for (var i in this.menu_items) 
      removeClass(this.menu_items[i], "selected");
    if (this.menu_items[name])
      addClass(this.menu_items[name], "selected");
  
    if (!(name in  this.dialogs_ele)) 
      this.load(name);
  
    if (this.last_dialog && name == this.last_dialog) 
        return;
    else if(this.last_dialog)  {
        removeClass(this.dialogs_ele[this.last_dialog], "show");
    }

    this.last_dialog = name;
    this.title_ele.textContent = this.title + name;
    addClass(ELE("container"), "show");
    addClass(ELE("dialogs"), "show");
    if (ontop) addClass(ELE("dialogs"), "ontop");
    addClass(this.dialogs_ele[name], "show");
  },
  load: function(name) {
    try {
      this.templates[name] = new EJS({
        url: './templates/' + name + '.ejs',
        type: '['
      });
      var dialog_ele = document.createElement("div");
      dialog_ele.id = this.prefix + name;
      dialog_ele.className = "dialog";
      this.dialogs_ele[name] = dialog_ele;
      this.templates[name].update(dialog_ele, {str: this.strings});
      Q("#container").appendChild(dialog_ele);
      var d = window[name];
      d.load();
      //for (var i in window) console.log(i);
      var closeicon_ele = dialog_ele.querySelector(".closeicon");
      if (closeicon_ele) 
        closeicon_ele.addEventListener("click", function() {
          Dialogs.close_dialog();
        });
    } catch(err) {
      log_error(err);
    }
  },
  close_dialog: function() {
    removeClass(Q("#container-background"), "show");
    removeClass(this.menu_items[this.last_dialog], "selected");
    removeClass(this.dialogs_ele[this.last_dialog], "show");
    this.last_dialog = null;
    this.title_ele.textContent = this.title + "manager";
    removeClass(ELE("container"),"show");
    removeClass(ELE("dialogs"),"show");
    removeClass(ELE("dialogs"),"ontop");
  }
}

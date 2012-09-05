function Tabs(ele) {
  this.ele = ele;
  this.menus = ele.querySelectorAll(".tab");
  this.contents = ele.querySelectorAll(".tabcontent");
  this.mmenus = [];

  var self = this;
  for (var i=0;i<this.menus.length;i++) {
    (function(m, name){
      m.nname = name;
      self.mmenus.push(m);
      m.onclick = function(evt) {
        try {
          if (hasClass(m, "selected") && hasClass(m, "expandable")) {
            toggleClass(m, "selected");
          } else if (hasClass(m,"expandable")) {
            self.hide();
            addClass(m, "selected");
          }
          self.updateTitles();
        } catch(err) {
          log_error(err);
        }
      }
    })(this.menus[i], this.menus[i].textContent);
    var sele = self.ele.querySelector('[name="'+this.menus[i].name+'-content"]');
    if (sele) {
      var li = document.createElement("div");
      sele.insertBefore(li, sele.firstChild);
      li.id = "log";
      li.setAttribute("name", "log");
    }
    if (hasClass(this.menus[i], "expandable")) {
      self.updateTitles();
    }
  }
}

Tabs.create = function(ele) {
  return new Tabs(ele);
}
Tabs.prototype.updateTitles = function() {
  for (var j=0;j<this.mmenus.length;j++) {
    var mm = this.mmenus[j];
    var sele = this.ele.querySelector('[name="'+mm.name+'-content"]');
    if (hasClass(mm, "expandable")) {
      var innerhtml = "<span class='tabexpand'>"; 
      if (hasClass(mm, "selected"))  {
        sele.style.display="block";
        innerhtml += "-";
      } else {
        sele.style.display="";
        innerhtml += "+";
      }
      mm.innerHTML = escapeHTML(innerhtml + "</span>" + mm.nname);
    }
  }
}

Tabs.prototype.get = function(tabname) {
  var self = this;
  var ret = { };
  ret.ele = this.ele.querySelector('[name="'+tabname+'-content"]'); 
  ret.message = function(str) {
    var tab = self.ele.parentNode.querySelector('[name="'+tabname+'-content"]'); 
    var log = tab.querySelector('[name="log"]');
    log.textContent = str;
    setTimeout(function() { log.innerHTML = "" }, 3000);
  }
  return ret;
}

Tabs.prototype.hide = function() {
  var content_tabs = this.ele.querySelectorAll(".tabcontent");
  for (var i=0;i<content_tabs.length;i++) 
    content_tabs[i].style.display = "none";

  for (var i=0;i<this.menus.length;i++) 
    removeClass(this.menus[i], "selected");
}

var Tabs2 = Tabs;

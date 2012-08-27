function Box(ele) {
  this.box_id = "";
  this.ele = ele;
  this.title = "";
  this.content = "";
  this.collapse_icon = "&#x25B6";
  this.expand_icon = "&#x25BC";
  this.close_icon = "&#x2613"
  this.onprogress_img = "/graphics/animated_progress.gif";
  this.onclose = [];
  this.onshow = [];
  this.onopen = [];
  this.onselect = [];
  this.selectable = false;
  this.selected = false;
  this.check_ele = null;
  this.expandable = true;
  this.expanded = false;
  this.closable = false;
  this.starthidden = false;
  this.progressbox = false;
  this.icon_ele = null;
  this.content_ele = null;
  this.expand_ele = null;
  this.header_ele = null;
}

Box.template = new EJS({
  url: './templates/box_template.ejs',
  type: '['
});

Box.prototype.trigger = function(evt_type) {
  var cbs = this[evt_type];
  for (var i=0; i<cbs.length; i++) {
    cbs[i](this);
  }
}

Box.prototype.show = function() {
  addClass(this.ele, "show");
  this.trigger("onshow");
}

Box.prototype.init = function () {
  this.ele = document.createElement("div");
  this.ele.className = "box-template";
  this.target_ele.appendChild(this.ele);
  Box.template.update(this.ele, this.serialize());
  this.icon_ele = this.ele.querySelector(".icon");
  this.title_ele = this.ele.querySelector(".title");
  this.header_ele = this.ele.querySelector(".box-header");
  this.content_ele = this.ele.querySelector(".box-content");
  var self = this;
  if (this.expandable) {
    this.expand_ele = this.ele.querySelector(".expand");
    this.expand_ele.onclick = function (evt) { 
      if (evt.ctrlKey) {
        self.setSelected(!self.selected);
        evt.stopPropagation();
        return false;
      }
      self.detailsToggle(); 
      if (self.expanded)
        self.trigger("onopen");
    };
  }
  if (this.progressbox) {
    this.icon_ele.onclick = function (e) {
      self.remove();
    };
  }
  if (this.selectable) {
    this.check_ele = this.ele.querySelector(".selector");
    this.check_ele.addEventListener("click", function(evt) {
      self.selected = evt.target.checked;
      if (self.selected) 
        addClass(self.ele, "selected");
      else
        removeClass(self.ele, "selected");
      self.trigger("onselect");
    });
    this.check_ele.addEventListener("change", function(evt) {
      self.selected = evt.target.checked;
      if (self.selected) 
        addClass(self.ele, "selected");
      else
        removeClass(self.ele, "selected");
      self.trigger("onselect");
    });
  }
  this.updateBox();
};

Box.prototype.updateBox = function () {
  this.content_ele.style.display = this.expanded ? "block" : "none";
  this.updateIcon();
}

Box.prototype.updateIcon = function () {
  if (this.progressbox) {
    addClass(this.header_ele, "progress");
    this.icon_ele.innerHTML = "<img src='" + this.onprogress_img + "' />"
  } 
  else if (this.expandable) {
      this.icon_ele.innerHTML = this.expanded ? this.expand_icon : this.collapse_icon;
  } else {
      this.icon_ele.innerHTML = this.close_icon;
  }
};


Box.prototype.detailsToggle = function() {
  this.expanded = !this.expanded;
  if (this.expanded) {
    addClass(this.icon_ele, "expanded")
    addClass(this.content_ele, "expanded")
  } else {
    removeClass(this.icon_ele, "expanded")
    removeClass(this.content_ele, "expanded")
  }
  this.updateBox();
};

Box.prototype.addEventListener = function(evt_type, func) {
  switch (evt_type) {
    case 'onclose':
      this.onclose.push(func);
      break;
    case 'onshow':
      this.onshow.push(func);
      break;
    case 'onopen':
      this.onopen.push(func);
      break;
    case 'onselect':
      this.onselect.push(func);
      break;
    default:
      throw "Event type " + evt_type + " not exists";
  }
}

Box.prototype.remove = function (parent) {
  this.ele.parentNode.removeChild(this.ele);
  this.trigger("onclose");
};

Box.prototype.getIcon = function () {
  return (this.expanded ? this.expand_icon : this.collapse_icon);
};

Box.prototype.serialize = function () {
  return {  
      box_id: this.box_id,
      title: this.title,
      content: this.content,
      icon: this.getIcon(),
      selectable: this.selectable,
      expandable : this.expandable,
      progressbox : this.progressbox,
  };
};

Box.prototype.updateTitle = function(title) {
  this.title = title;
  this.title_ele.innerHTML = title;
}

Box.prototype.stopProgress = function() {
  this.progressbox = false;
  addClass(this.icon_ele, "closable");
  this.updateIcon();
}
Box.prototype.setSelected = function(selected) {
  this.selected = selected;
  this.check_ele.checked = selected;
  var ev = document.createEvent('HTMLEvents');
  ev.initEvent('change', true, false);
  this.check_ele.dispatchEvent(ev);
}

Box.create = function(target_ele, id, title, content, opts) {
  var box = new Box();
  box.target_ele = target_ele;
  box.id = id;
  box.title = title
  box.content = content
  box.opts = opts || {};
  box.expanded = box.opts.expanded || false;
  box.expandable = (box.opts.expandable == false) ? false : true;
  box.selectable = box.opts.selectable || false;
  box.progressbox = box.opts.progressbox || false;
  box.init();
  if (box.expanded) {
    box.expanded = false;
    box.detailsToggle();
  }

  return box;
}


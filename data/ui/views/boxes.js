function Boxes(target) {
  this.list = [];
  this.target = target;
  var self = this;
  this.createImport = function(title, extend, hidden) {
    var box = this.create(title, extend, hidden);
    box.new_keys = 0;
    box.updated_keys = 0;
    box.unchanged_keys = 0;
    box.error_keys = 0;
    return box;
  }
  this.create = function(title, extend, hidden) {
    //var li = document.createElement("li");
    var ts = new Date().getTime();
    var box_id = "box-container-" + ts;
    //this.target.insertBefore(li, target.firstChild);
    //li.className = "box-container";
    var box = Box.create(this.target, box_id, title, "", {hidden:hidden || false, expanded:true, expandable: false, expandable: false,progressbox:true});
    box.ts = ts;
    box.addEventListener("onclose", function() {
      try {
        if (!self.target.childNodes.length)
          removeClass(self.target, "nonempty");
      } catch(err) {
        log_error(err);
      };
    });
    if (hidden==true)
      box.addEventListener("onshow", function() {
        addClass(self.target, "nonempty");
      });
    else
      addClass(this.target, "nonempty");

    addClass(box.content_ele, "setmargin");
    for (var i in extend) box[i] = extend[i];
    this.list.push(box);
    return box;
  };
  this.get = function(ts) {
    for (var i=0;i<this.list.length;i++) {
      if (this.list[i].ts == ts) {
        return this.list[i];
      }
    }
    return null;
  };
}

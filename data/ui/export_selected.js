
var export_selected = {
  ele: null,
  boxes: null,
  box: null,
  button_ele: null,
  results_ele: null,
  input_ele: null,
  keyids: [],
  Q: function(query) {
    return this.ele.querySelector(query); 
  },
  export_keyids: function(keyids) {
    var self = this;
    this.keyids = keyids;
    ONCE("pgp-pubexported", function(res) {
      self.Q("pre").innerHTML = res.armored_key;
    });
    EMIT("pgp-pubexport", {keyids: keyids});
  },
  load: function() {
    var self = this;
    this.ele = document.getElementById("dialog-export_selected");
    var tofile = this.Q("button[name='tofile']");
    tofile.addEventListener("click", function(evt) {
      ONCE("pgp-exportedto", function(res) {
        self.message(res.msg);
      });
      EMIT("pgp-export", {keyids: self.keyids, to:"tofile"});
    });
    var toclipboard = this.Q("button[name='toclipboard']");
    toclipboard.addEventListener("click", function(evt) {
      ONCE("pgp-exportedto", function(res) {
        self.message(res.msg);
      });
      EMIT("pgp-export", {keyids: self.keyids, to:"toclipboard"});
    });
  },
  message: function(msg) {
    this.Q(".message").textContent = msg;
    setTimeout(function() {
    this.Q(".message").textContent = "";
    }, 2000);
  }
}

var Panel = {
  ele: null,
  template: null,
  strings: null,
  Q: function(query) {
    return this.ele.querySelector(query);
  },
  init: function(options) {
    this.ele = document.getElementById("nav_menu");
    this.strings = fetch_lang_file(options.lang);

    this.template = new EJS({
      url: './templates/panel.ejs',
      type: '['
    });
    this.template.update(this.ele, {str: this.strings});

    var self = this;
    this.Q("#section-genkey").onclick = function() {
      EMIT('open-section', 'genkey');
    }
    this.Q("#section-import").onclick = function() {
      EMIT('open-section', 'import_keys');
    }
    this.Q("#section-encrypt").onclick = function() {
      EMIT('open-section', 'encrypt');
    }
    this.Q("#section-decrypt").onclick = function() {
      EMIT('open-section', 'decrypt');
    }
    this.Q("#section-sign").onclick = function() {
      EMIT('open-section', 'sign');
    }
    this.Q("#section-verify").onclick = function() {
      EMIT('open-section', 'verify');
    }
    this.Q("#section-manager").onclick = function() {
      EMIT('open-section', 'manager');
    }
    this.Q("#section-options").onclick = function() {
      EMIT('open-section', 'options');
    }
  }
}

const data = require('self').data;
const sprintf = require('util/sprintf').sprintf;

var lang = null;
var lang_strings = null;

exports.getLang = function() {
  return lang;
}

exports.setLang = function(_lang) {
  lang = _lang;
  var lang_file = data.load('languages/' + lang + '.json');
  lang_strings = JSON.parse(lang_file);
}

exports.getStr = function(argument) {
  if (lang == null) 
    this.setLang("en");

  var arg = arguments[0];
  var ret = "";

  if (lang_strings && (arg in lang_strings))
    arguments[0] = lang_strings[arg];
  else
    arguments[0] = "Missing lang load or lang string: " + arg;

  return sprintf.apply(this, arguments);
}

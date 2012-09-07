var sprintf = require('util/sprintf').sprintf;
var DEBUG = false;
const misc = require('util/misc');

function Logger(title) {

  this.stdout = DEBUG;
  this.title = title || ""; 
  this.logging = [];
  
  function align(tab, toalign) {
    let len = tab.length; 
    let str = "";
    for (let i=0; i<len; i++)
      str += " ";
    toalign = toalign || "";
    toalign = toalign.replace(/\t/g, "");
    toalign = toalign.replace(/\n/g, "\n" + str);
    return toalign;
  }

  this.log = function(type, args) {
    var str = sprintf.apply(this, args);
    //if (this.stdout)
    //  console.log("\r" + str);
    this.logging.push([this.title, type, str]);
  }

  this.error = function() {
    var arg0 = arguments[0];
    var errStr = "";
    if (Object.prototype.toString.call(arg0).indexOf("WorkerErrorEvent") >= 0) {
      errStr = "Worker Error: " + arg0.message +
               "\nWorker Error filename: " + arg0.filename +
               "\nWorker Error line no: " + arg0.lineno;
    } else if (Object.prototype.toString.call(arg0).indexOf("Error") >= 0) {
      errStr = arg0.lineNumber+" :: "+arg0.fileName+"\n"+arg0.toString();
    } else 
      errStr = sprintf.apply(this, arg0);
    console.error(errStr);
  }

  this.debug = function() {
    this.log("debug", arguments);
  }

  this.warn = function() {
    this.log("warning", arguments);
  }

  this.func = function(str) {
    if (str)
      this.log("func", arguments);

  }

  this.info = function() {
    this.log("info", arguments);
  }

  this.hex_dump = function(bytearray) {
    var seq;
    var str = "";
    if (typeof bytearray == "string") {
      var b = [];
      for (var i=0; i < bytearray.length; i++) 
        b.push(bytearray.charCodeAt(i));
      seq = b;
      str = sprintf("string length %d bytes\n", seq.length);
    } else {
      seq = bytearray;
      str = sprintf("array length %d bytes\n", seq.length);
    }


    for (var i=0;i<seq.length;i++) {
      str = str + ("0"+seq[i].toString(16)).slice(-2).toUpperCase() + " ";
      if (((i + 1) % 8) == 0) str += "  ";
      if (((i + 1) % 16) == 0) str += "\n";
    }
    console.log(str);
  }
}

exports.create = function(title) { 
  return new Logger(title);
};

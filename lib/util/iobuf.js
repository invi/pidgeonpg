
const {Cc, Ci} = require("chrome");

//converts string to readable stream
function StringBuf(str) 
{
	let strstream = Cc["@mozilla.org/io/string-input-stream;1"].
	             createInstance(Ci.nsIStringInputStream);
	strstream.setData(str, str.length);

	let binstream = Cc["@mozilla.org/binaryinputstream;1"].
	             createInstance(Ci.nsIObjectInputStream);
	binstream.setInputStream(strstream);

	return binstream;
}

function IOBuf(inp) 
{
  try {
    this.inp = (typeof inp == "string") ? StringBuf(inp) : inp;
    this.len = this.inp.available();
  } catch(e) {
    console.trace();
    throw e;
  }
    
}

IOBuf.prototype.where = function() 
{
  return (this.len - this.inp.available()) + " in " + this.len;
}

IOBuf.prototype.read32 = function() 
{
  if (this.inp.available() > 3)
	  return this.inp.read32();
  else
	  return -1;
}

IOBuf.prototype.read16 = function() 
{
  if (this.inp.available() > 1)
	  return this.inp.read16();
  else
	  return -1;
}

IOBuf.prototype.read = function(obj) 
{
	var c = [ ],
      len = obj.len;
  
	for (; len; len--) 
  {
    c.push(this.inp.read8());
	}
	obj.data = c;
	return c.length - len;
}

IOBuf.prototype.read_len = function(len) 
{
  var obj = { len: len }
  this.read(obj);
  return obj.data;
}

IOBuf.prototype.get = function() 
{
  if (this.inp.available())
    return this.inp.read8();
  else
    return -1;
}
IOBuf.prototype.getChar = function() 
{
  if (this.inp.available())
    return String.fromCharCode(this.inp.read8());
  else
    return -1;
}

IOBuf.prototype.readString = function(len) {
  var ret = "";
  while (len--) 
    ret += this.getChar();

  return ret;
}

IOBuf.prototype.read_rest = function() 
{
  var ret = "";
  var ret2 =  [ ];
  while (this.inp.available()) {
     var val = this.get();
     ret += String.fromCharCode(val);
     ret2.push(val);
  }
  return ret;
}

IOBuf.prototype.skip_rest = function(len) 
{
 if (len > this.inp.available()) {
   throw "Error skip";
 }
 for (; len; len--) {
    this.inp.read8();
 }
}

exports.IOBuf = IOBuf;


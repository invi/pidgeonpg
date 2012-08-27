const misc = require("util/misc");
const getStr = require("util/lang").getStr;

let Trait = require('light-traits').Trait;

function pad(n){return n<10 ? '0'+n : n};

let t = Trait({
  getCreationDate : function() {
    var d = new Date( this.getPacket().timestamp * 1000 )
    return d.getDate() + "/" + pad(d.getMonth() + 1)  + "/" + (d.getYear() + 1900);
  },
  getExpirationDate : function() {
    if (!('expiredate' in this.getPacket()))
      return getStr("never");
    if (this.getPacket().timestamp == this.getPacket().expiredate)
      return getStr("never");
    var d = new Date(this.getPacket().expiredate * 1000 )
    return d.getDate() + "/" + pad(d.getMonth() + 1)  + "/" + (d.getYear() + 1900);
  },
  getProtectedStr: function() {
    return getStr(this.isProtected() ? "protected" : "not_protected");
  },
});

exports.FormatTrait = t;

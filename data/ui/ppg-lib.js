const ELE = document.getElementById;
const E = document.getElementById;
const Q = document.querySelector;
const EMIT = self.port.emit;
const ON = self.port.on;
const ONCE = self.port.once;
//const setTimeout = self.setTimeout;

function buildUserId(name, comment, email) {
   return  name + 
           ((comment != "") ? " (" + comment + ")" : "") +
           ((email != "") ? " <" + email + ">" : "");
}


const PGP = { 
  "KEYSTATUS": 
    {"NEW": 0, "CHANGED": 1, "UNCHANGED": 2}
};

const ALGO = {
    RSA: 1, 
    RSA_E: 2,
    RSA_S: 3,
    ELGAMAL_E: 16, 
    DSA: 17, 
    ECDH: 18, 
    ECDSA: 19,
    ELGAMAL: 20
};

var getStatsStr = function(box) {
  return "Keys: new " + box.new_keys + 
              ", updated: " + box.updated_keys +
              ", unchanged: " + box.unchanged_keys +
              ", errors: " + box.error_keys;
}

function getStr(str, str1, str2) {
  var ret;
  try {
    ret = (sprintf(strings[str], str1, str2));
  } catch(e) {
    ret = str;
  }
  return ret;
}

function timeformat(ts) {
  var ret = new Date(ts);
  var h=ret.getHours();
  var m=ret.getMinutes();
  var s=ret.getSeconds();
  return ("0" + h).slice(-2) + ":" + ("0" + m).slice(-2) + ":" + ("0" + s).slice(-2);

}

function createSaveButtons(ele, resmsg, details) {
  ele.innerHTML = "<div name='copymenu'><div name=\"msg\"></div>" +
    "<button name=\"toclipboard\">" + getStr("clipboard") + "</button>" +
    "<button name=\"tofile\">" + getStr("file") + "</button></div>" +
    "<div name='box-result'>" + details + "</div>";
  var msg = ele.querySelector("div[name='msg']");
  var tm = null;
  msg.notify = function(msg2) {
    if (tm) clearTimeout(tm);
    msg.innerHTML = msg2;
    tm=setTimeout(function() { msg.innerHTML = ''}, 4000);
  }
  var tofile = ele.querySelector("button[name='tofile']");
  tofile.addEventListener("click", function(evt) {
    ONCE("savedtofile", function(res) {
      msg.notify(res.msg);
    });
    EMIT("savetofile", resmsg);
  });
  var toclipboard = ele.querySelector("button[name='toclipboard']");
  toclipboard.addEventListener("click", function(evt) {
    EMIT("clipboard-copy", resmsg);
    msg.notify("Copied to clipboard!");
  });
}

function getExpireSeconds(format, t) {
  if (format == "never") 
    return 0;
  var now = new Date();
  const days = { never: 0, days: 1, weeks: 7, months: 30, years: 365.25};
  return t * days[format] * 24 * 3600;
}

function countProperties(obj) {
  var prop;
  var propCount = 0;

  for (prop in obj) {
    propCount++;
  }
  return propCount;
}

function escapeHTML(s) {
  var MAP = {
    'α': '&aacute;',
    'ι': '&eacute;',
    'ν': '&iacute;',
    'σ': '&oacute;',
    'ϊ': '&uacute;',
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&#34;',
    "'": '&#39;'
  };
  var repl = function(c) { return MAP[c]; };
  return s.replace(/[αινσϊ&<>'"]/g, repl);
}

var notify = {
  error: function(msg) {
    alert(msg);
    //var div = document.createElement("div");
    //div.style.display = "hidden";
    //div.innerHTML = "<div class='msg'><button class=\"close\" style=\"display:inline\">" + getStr("close") + "</button><div style=\"margin-left:20px;display:inline\">" + msg + "</div></div>";
    //var cont = document.getElementById("notifications");
    //cont.insertBefore(div, cont.firstChild);
    //div.querySelector(".close").onclick = function(evt) {
    //  div.parentNode.removeChild(div);
    //}
    //function hide() {
    //  addClass(div, "fade");
    //}
    //function remove() {
    //  if (div.parentNode)
    //    div.parentNode.removeChild(div);
    //}
    //setTimeout(hide, 6000);
    //setTimeout(remove, 7000);
  },
  confirm: function(msg, callback) {
    var res = confirm(msg);
    callback(res);
//    var div = document.createElement("div");
//    div.style.display = "hidden";
//    //div.style.setProperty("z-index", "1000");
//    div.innerHTML = "<div class='msg'><div>" + msg + "</div><br /><button class=\"continue\" style=\"margin:10px\">" + 
//                    getStr("continue") + "</button><button class=\"cancel\" style=\"margin:10px\">" + 
//                    getStr("cancel") + "</button></div>";
//    var cont = document.getElementById("notifications");
//    cont.insertBefore(div, cont.firstChild);
//
//    var div_back = document.createElement("div");
//    div_back.className = "background";
//    cont.insertBefore(div_back, cont.firstChild);
//    document.onkeydown = function(evt) {
//      if ((evt.keyCode) == 27) {
//        div_back.parentNode.removeChild(div_back);
//        div.parentNode.removeChild(div);
//        document.onkeydown = null;
//      }
//    }
//    div.querySelector(".continue").onclick = function(evt) {
//      div_back.parentNode.removeChild(div_back);
//      div.parentNode.removeChild(div);
//      callback(true);
//    }
//    div.querySelector(".continue").focus();
//    div.querySelector(".cancel").onclick = function(evt) {
//      div_back.parentNode.removeChild(div_back);
//      div.parentNode.removeChild(div);
//      callback(false);
//    }
//    div.style.display = "block";
  }
}

function progress_bar(ele, text) {
  ele.innerHTML = '<center><img src="../graphics/animated_progress.gif" /><h1>' + escapeHTML(text) + '</h1></center>';
}

function collect() {
  var ret = {};
  var len = arguments.length;
  for (var i=0; i<len; i++) {
    for (p in arguments[i]) 
      if (arguments[i].hasOwnProperty(p))
        ret[p] = arguments[i][p];
  }
  return ret;
}

/* Select utils */
function getSelected(select) {
  if (typeof select == "undefined")
    return {};
  for (var i = 0; i < select.childNodes.length; i++)
    if (select.childNodes[i].selected)
      return {
          value: select.childNodes[i].value,
          text:  select.childNodes[i].text 
      };
  return {};
}

function setDefaultOption(select, value) {
  log_debug("setting default option = " + value);
  log_debug("previous option was " + select.options[select.selectedIndex].value);
  for (var i=0; i<select.options.length;i++)
    if (select.options[i].value == value) {
      select.options[i].selected = "1";
      select.selectedIndex = i;
      log_debug("Selected option " + i + "(" + value + ")");
      return true;
    }
  return false;
}

function clearSelect(select) {
  if (typeof select != "undefined")
    select.innerHTML="";
}

function addOption(target, content, value, selected) {
    var opele = document.createElement("option");
    opele.textContent = (selected ? "* " : "") + content;
    opele.value = value || "";
    opele.selected = selected || false;
    target.appendChild(opele);
}

function fillSelect(select, keylist, default_key) {
  var key;
  var opele; 
  clearSelect(select); 
  if (keylist.length == 0) 
    addOption(select, getStr("no_keys"), "", true);
  else {
    addOption(select,  getStr("select_key"), "", false);
    for (var i=0; i<keylist.length; i++) {
      key = keylist[i];
      var content = "[" + key.short_id + "] " + key.uids[0].name;
      var value = key.id;
      addOption(select, content, value, value == default_key);
    }
  } 
}
/* End of select utils */

function hasClass(ele,cls) {
  if (ele)
    return ele.className.match(new RegExp('(\\s|^)'+cls+'(\\s|$)'));
}
 
function addClass(ele,cls) {
  if (ele)
    if (!this.hasClass(ele,cls)) ele.className += " "+cls;
}
  
function removeClass(ele,cls) {
  if (hasClass(ele,cls)) {
    var reg = new RegExp('(\\s|^)'+cls+'(\\s|$)');
    ele.className=ele.className.replace(reg,' ');
  }
}

function toggleClass(ele,cls) {
  if (hasClass(ele,cls)) {
    var reg = new RegExp('(\\s|^)'+cls+'(\\s|$)');
    ele.className=ele.className.replace(reg,' ');
  }
  else
    addClass(ele,cls);
}

function singleChildClass(ele, cls) {
  var children = ele.parentNode.childNodes
  for (var i=0; i<children.length; i++) {
    var c = children[i];
    if (c != ele) removeClass(c, cls);
  }
  hasClass(ele,cls) ? toggleClass(ele, cls) : addClass(ele, cls);
}

function fetch_lang_file(lang) {
  var httpRequest = new XMLHttpRequest();
  httpRequest.open('GET', '../languages/' + lang + '.json', false); 
  httpRequest.send();
  var ret = JSON.parse(httpRequest.responseText);
  log_debug("Fetched:" + lang);
  return ret;
}

function emailValidation(email_ele) {
  var filter = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  var valid = email_ele.value == "" || filter.test(email_ele.value);
  if (!valid) {
    addClass(email_ele, "field-error");
    notify.error(getStr("email_error"));
  } else
    removeClass(email_ele, "field-error");
  return valid;
}

function log_error(arg0) {
  var err = arg0.lineNumber+" :: "+arg0.fileName+"\n"+arg0.toString();
  console.log(err);
  return err;
}

function log_debug(arg0) {
  console.debug(arg0);
}

function passphraseValidation(use_pass, p1, p2) {
  var valid = !use_pass || (p1.value.length > 0 &&  p1.value == p2.value);
  if (!valid) {
    addClass(p1, "field-error");
    addClass(p2, "field-error");
    if (p1.value == "")
      notify.error(getStr("passphrase_empty"));
    else
      notify.error(getStr("passphrase_mismatch"));
  } else {
    removeClass(p1, "field-error");
    removeClass(p2, "field-error");
  }
  return valid;
}

function expiredateValidation(expire_format, expiredate) {
  var valid = expire_format == "never" || !isNaN(parseInt(expiredate.value));
  if (!valid) {
    notify.error(getStr("expiration_typeerror"));
    addClass(expiredate, "field-error");
  } else {
    removeClass(expiredate, "field-error");
  }
  return valid;
}

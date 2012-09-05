const widgets = require("widget");
const data = require('self').data;
const tabs = require("tabs");
const file = require('file');
let clipboard = require("clipboard");
const keyserver = require('util/hkp');
const {ppgapp} = require('ppgapp');
const {getStr} = require("util/lang");
const {storage} = require('ring/storage');
const {filePicker, saveFilePicker} = require('util/filepicker');
const logger = require('util/logger').create("main.js");
const wu = require("window-utils");



let mappings = [];
var location = undefined;
var apptab = undefined;

//var pageMod = require("page-mod");
//pageMod.PageMod({
//  include: "*",
//  contentScript: 'var dataurl = "' + data.url() + '";RoundCube.init(dataurl);',
//  contentScriptFile: [
//                       data.url("ui/ejs_production.js"),
//                       data.url("ui/ppg-lib.js"),
//                       data.url('ui/views/box.js'),
//                       data.url('ui/views/boxes.js'),
//                       data.url('ui/views/keylist_view.js'),
//                       data.url('ui/views/key_view.js'),
//                       data.url('ui/views/key_subkey_view.js'),
//                       data.url('ui/views/key_uid_view.js'),
//                       data.url('ui/views/key_uidsig_view.js'),
//                       data.url('ui/sprintf.js'),
//                       data.url('ui/tabs.js'),
//                       data.url("ui/firegpg.js"),
//                       data.url("ui/firegpg-inline.js"),
//                       data.url("ui/firegpg-cselect.js"),
//                       data.url("ui/rc.js"),
//                     ],
//  contentScriptWhen: 'end',
//  onAttach: function onAttach(worker) {
//    load_events(worker);
//  }
//});

function start(chromeWindow) {
  let XULBrowserWindow = chromeWindow.XULBrowserWindow;
  let originalFunction = XULBrowserWindow.hideChromeForLocation;

  mappings.push({window: chromeWindow, originalFunction: originalFunction});

  XULBrowserWindow.hideChromeForLocation = function(aLocation) {
    return originalFunction.call(XULBrowserWindow, aLocation) || (aLocation == apptab.url);
  }
}

function stop(chromeWindow) {
  for (let i in mappings) {
    let pair = mappings[i];
    if (chromeWindow === pair.window) {
      chromeWindow.XULBrowserWindow.hideChromeForLocation = pair.originalFunction;
      mappings.splice(i,1);
      break;
    }
  }
}

function triggerOnLocationChange(event) {
  let win = event.target.ownerDocument.defaultView;
  win.XULBrowserWindow.onLocationChange(
    {DOMWindow: win.content}, /* stub aWebProgress obj */
    null,
    win.gBrowser.selectedTab.location
  );
}

var delegate = {
  onTrack: function (window) start(window),
  onUntrack: function (window) stop(window)
}

new wu.WindowTracker(delegate);

function sectionsContentScripts() {
  var options = storage.get_all_options();
  return "\nUI.init( " + JSON.stringify(options) + ");";
}

function load_events(worker){
  //* list of events *//
  // pgp-key-generate --> <-- pgp-key-generated
  //                      <-- pgp-key-imported
  // pgp-key-parse    --> <-- pgp-key-parsed
  // pgp-key-import   --> <-- pgp-key-imported
  // pgp-key-remove   --> <-- pgp-key-removed

  // pgp-msg-decrypt  --> <-- pgp-msg-decrypted
  // pgp-msg-encrypt  --> <-- pgp-msg-encrypted

  // pgp-msg-sign     --> <-- pgp-msg-signed
  // pgp-msg-verify   --> <-- pgp-msg-verified
  //                      <-- pgp-key-list
  
  // pgp-ui-open      --> 
  //                      <-- pgp-ui-open

  //pgp-fetch-keyring --> <-- pgp-fetched-keyring
  worker.port.on("pgp-pubexport", function(params) {
    var response = {rc: 0, armored_key: "", msg: ""};
    try { 
      response.armored_key = ppgapp.exportPublic(params.keyids);
      worker.port.emit("pgp-pubexported", response);
    } catch(e) {
      logger.error(e);
      response.rc = -1;
      response.msg = e.toString();
      worker.port.emit("pgp-pubexported", response);
    }
  });
  worker.port.on("pgp-secexport", function(params) {
    var response = {rc: 0, armored_key: "", msg: ""};
    try { 
      response.armored_key = ppgapp.exportSecret(params.keyid);
      worker.port.emit("pgp-secexported", response);
    } catch(e) {
      response.rc = -1;
      response.msg = e.toString();
      worker.port.emit("pgp-secexported", response);
    }
  });
  worker.port.on("pgp-secexportto", function(params) {
    var {keyid, to} = params;
    res = { rc: 0, msg: "" };
    switch(to) {
      case "toclipboard":
        clipboard.set(ppgapp.exportSecret(keyid));
        res.msg = "Copied to clipboard!";
        worker.port.emit("pgp-exportedto", res);
        break;
      case "tofile":
        var filename = saveFilePicker().path;
        if (filename) {
          var stream = file.open(filename, "w");
          if (stream) 
            try {
              stream.write(ppgapp.exportSecret(keyid));
              stream.close();
              res.msg = "Exported to file " + filename;
            } catch(e) {
              res.msg = e.toString();
            }
          else 
            res.msg = "Open file " + filename + " failed";
        } else {
          res.msg = "Export cancelled!";
        }
        break;
      default: 
        res.rc = -1;
        res.msg = "Bug: unkown export method " + to;
    }
    worker.port.emit("pgp-exportedto", res);
  });
  worker.port.on("pgp-export", function(params) {
    var {keyids, to} = params;
    res = { rc: 0, msg: "" };
    switch(to) {
      case "toclipboard":
        clipboard.set(ppgapp.exportPublic(keyids));
        res.msg = "Copied to clipboard!";
        worker.port.emit("pgp-exportedto", res);
        break;
      case "tofile":
        var filename = saveFilePicker().path;
        if (filename) {
          var stream = file.open(filename, "w");
          if (stream) 
            try {
              stream.write(ppgapp.exportPublic(keyids));
              stream.close();
              res.msg = "Exported to file " + filename;
            } catch(e) {
              res.msg = e.toString();
            }
          else 
            res.msg = "Open file " + filename + " failed";
        } else {
          res.msg = "Export cancelled!";
        }
        break;
      case "tokeyserver":
        res.rc = -1;
        res.msg = "Export key server not implemented";
        break;
      default: 
        res.rc = -1;
        res.msg = "Bug: unkown export method " + to;
    }
    worker.port.emit("pgp-exportedto", res);
  });
  worker.port.on("savetofile", function(text) {
    var res = {rc: 0, msg: ""};
    var filename = saveFilePicker().path;
    if (filename) {
      res.filename = filename;
      var stream = file.open(filename, "w");
      if (stream) 
        try {
          stream.write(text);
          stream.close();
          res.msg = "Saved to file " + filename;
        } catch(e) {
          res.msg = e.toString();
        }
      else  {
        res.rc = -1;
        res.msg = "Open file " + filename + " failed";
      }
    } else {
      res.rc = 1;
      res.msg = "Save to file cancelled!";
    }
    worker.port.emit("savedtofile", res);
  });
  worker.port.on("clipboard-copy", function(text) {
    clipboard.set(text);  
  });
  worker.port.on("pgp-create-uid", function(req) {
    var res = {rc: 0, msg: ""};
    ppgapp.generateUserId(req.keyid, req.options, function(err, key, uid) {
      if (err) {
        res.rc = -1;
        res.msg = err.toString();
      } else {
        res.msg = "Create User Id " + uid.name;
        res.key = key;
        res.uid = uid;
        worker.port.emit("pgp-created-uid", res);
      }
    });
  });
  worker.port.on("pgp-update-uid-selfsig", function(req) {
    var res = {rc: 0, uid_num: req.uid_num, msg: ""};
    ppgapp.editUserId(req.keyid, req.uid_num, req.expireseconds, 
      function(err, key, uid) {
        if (err) {
          res.rc = -1;
          res.msg = err.toString();
        } else {
          res.key = key;
          res.uid = uid;
        }
        worker.port.emit("pgp-updated-uid-selfsig", res);
      }
    );
  });
  worker.port.on("pgp-create-subkey", function(req) {
    var res = {rc: 0, msg: ""};
    ppgapp.generateSubkey(req.keyid, req.options, function(err, key, subkey) {
      if (err) {
        res.rc = -1;
        res.msg = err.toString();
      } else {
        res.msg = "Created subkey " + subkey.id;
        res.key = key;
        res.subkey = subkey;
        worker.port.emit("pgp-created-subkey", res);
      }
    });
  });
  worker.port.on("pgp-revoke-key", function(req) {
    var result = {rc:0, keyid:req.keyid};
    req.reason = req.reason || "Revoked from PidgeonPG-UI";
    req.comment = req.comment || '';
    try {
      ppgapp.revokeKey(req.keyid, req.reason, req.comment, function(err, key) {
        result.key = key;
        result.msg = "Key Revoked: keyid=" + key.id;
        worker.port.emit("pgp-revoked-key", result);
      });
    } catch(e) {
      result.msg = "Key " + result.keyid + " was not revoked: " + e.toString();
      result.rc = -1;
      worker.port.emit("pgp-revoked-key", result);
    }
  });
  worker.port.on("pgp-revoke-uid", function(req) {
    var result = {rc:0, keyid:req.keyid};
    req.reason = req.reason || "Revoked from PidgeonPG-UI";
    req.comment = req.comment || '';
    try {
      ppgapp.revokeUserId(req.keyid, req.uid_index, req.reason, req.comment, function(err, key, uid) {
        result.key = key;
        result.uid = uid;
        result.msg = "Key Revoked: keyid=" + result.key.id;
        worker.port.emit("pgp-revoked-uid", result);
      });
    } catch(e) {
      result.msg = "Key " + req.keyid + " was not revoked: " + e.toString();
      result.rc = -1;
      worker.port.emit("pgp-revoked-uid", result);
    }
  });
  worker.port.on("pgp-revoke-subkey", function(req) {
    var result = {rc:0, keyid:req.subkeyid};
    req.reason = req.reason || "Revoked from PidgeonPG-UI";
    req.comment = req.comment || '';
    try {
      ppgapp.revokeSubkey(req.subkeyid, req.reason, req.comment, function(err, key, subkey) {
        result.key = key;
        result.subkey = subkey;
        result.msg = "Subkey revoked: keyid=" + result.subkey.id;
        worker.port.emit("pgp-revoked-subkey", result);
      });
    } catch(e) {
      result.msg = "Key " + req.subkeyid + " was not revoked: " + e.toString();
      result.rc = -1;
      worker.port.emit("pgp-revoked-uid", result);
    }
  });
  worker.port.on("pgp-sign-uid", function(keyid_str, uid_name) {
    var res = {rc: 0, msg: ""};
    try {
      ppgapp.signUserId(keyid_str, uid_name, function(key, uid, uid_num) {
        res.key = key;
        res.uid = uid;
        res.uid_num = uid_num;
        worker.port.emit("pgp-signed-uid", res);
      });
    } catch (e) {
      res.rc = -1;
      res.msg = "Could't sign user id";
      worker.port.emit("pgp-signed-uid", res);
    }
  });
  worker.port.on("keyserver-search", function(req) {
    var res = {rc: 0, ts: req.ts, keys: null};
    var ks = new keyserver.KeyServer(storage.get_option("keyserver"));
    ks.search(req.text, function (err, serverkeys) {
      if (err) {
        res.rc = "-1";
        res.msg = err.toString();
      } else 
        res.keys = serverkeys;
      worker.port.emit("keyserver-search-result", res);
    });
  });

  worker.port.on("pgp-options-get-all", function() {
    worker.port.emit("pgp-options-got-all", storage.get_all_options());
  });
  worker.port.on("pgp-option-get-keyserver", function(value) {
    worker.port.emit("pgp-option-got-keyserver", storage.get_option("keyserver"));
  });
  worker.port.on("pgp-options-set", function(option, value) {
    try {
      storage.set_option(option, value);
      switch (option) {
        case "lang":
          language = value;
          worker.port.emit("pgp-option-set-language", value);
          break;
        case "keyserver":
          worker.port.emit("pgp-option-set-keyserver", value);
          break;
        case "defaultkey":
          worker.port.emit("pgp-option-set-defaultkey", value);
          break;
      }
    } catch(e) {
      var ret = { option: option,
                  value:  value,
                  error:  e.toString()};
      worker.port.emit("pgp-option-set-error", ret);
    }
  });

  worker.port.on("pgp-key-parse", function(type, ts, keyids, text) {
    var keydata = "";
    var response = { rc   : 0,
                     ts   : ts,
                     msg  : "",
                     keydata : "",
                     keys : [] }
    switch(type) {
      case "file":
        if (pickedfile = filePicker()) {
          keydata = file.read(pickedfile.path);
          response.msg = getStr("fromfile") + pickedfile.path;
          ppgapp.importData(keydata, function(formatted_key) {
            if (formatted_key == null) {
              worker.port.emit("pgp-keyblock-parsed", response);
            } else {
              response.key = formatted_key;
              worker.port.emit("pgp-key-imported", response);
            }
          });
            
        } else {
          response.rc = "-1";
          response.msg = getStr("selcancel");
          worker.port.emit("pgp-keyblock-parsed", response);
        }
        break;
      case "text":
        keydata = text;
        if (keydata) {
          var foundany = false;
          ppgapp.importData(keydata, function(formatted_key) {
            //XXX error no callback sometimes!
            if (formatted_key != null) {
              foundany = true;
              response.key = formatted_key;
              worker.port.emit("pgp-key-imported", response);
            } else {
              response.keydata = keydata;
              response.msg = foundany ? getStr("fromclipboard") :
                                        getStr("errfromclipboard");
              worker.port.emit("pgp-keyblock-parsed", response);
            }
          });
        } else {
          response.rc = "-2";
          response.msg = getStr("selcancel");
          worker.port.emit("pgp-keyblock-parsed", response);
        }
        break;
      case "clipboard":
        keydata = clipboard.get();
        if (keydata) {
          var foundany = false;
          ppgapp.importData(keydata, function(formatted_key) {
            //XXX error no callback sometimes!
            if (formatted_key != null) {
              foundany = true;
              response.key = formatted_key;
              worker.port.emit("pgp-key-imported", response);
            } else {
              response.keydata = keydata;
              response.msg = foundany ? getStr("fromclipboard") :
                                        getStr("errfromclipboard");
              worker.port.emit("pgp-keyblock-parsed", response);
            }
          });
        } else {
          response.rc = "-2";
          response.msg = getStr("selcancel");
          worker.port.emit("pgp-keyblock-parsed", response);
        }
        break;
      case "keyserver":
        var ks = new keyserver.KeyServer(storage.get_option("keyserver"));
        var count = 0;
        for (var i=0; i < keyids.length; i++) {
          ks.get(keyids[i], function (err, keydata) {            
            var res = { rc: 0, ts: ts, msg: "", keydata: "", keys : [] };
            if (err==null) {
              res.msg = "Imported from keyserver";
              ppgapp.importData(keydata, function(formatted_key) {
                if (formatted_key) {
                  count++;
                  res.key = formatted_key;
                  worker.port.emit("pgp-key-imported", res);
                } else if (count == keyids.length) {
                  worker.port.emit("pgp-keyblock-parsed", res);
                }
              });
            } else {
              count++;
              res.rc = "-3";
              res.msg  = err.toString();
              if (count == keyids.length)
                worker.port.emit("pgp-keyblock-parsed", res);
              else
                worker.port.emit("pgp-key-imported", res);
            }
          });
        }
        break;
      default:
        response.rc = "-4";
        response.msg  = "ERROR: unknow importing source";
        worker.port.emit("pgp-keyblock-parsed", response);
        logger.error("Unknown importing source");
    }
  });


  worker.port.on("pgp-key-generate", function(params) {
    var res = {rc: 0, ts: params.seqts};
    ppgapp.generateKeypair(params, function(err, key) {
      if (err) {
        res.rc = -1;
        res.msg = err.toString();
      } else {
        res.key = key;
        res.msg = getStr("generated", key.id);
        worker.port.emit("pgp-key-imported", res);
      }
      worker.port.emit("pgp-key-generated", res);
    });
  });

  worker.port.on("pgp-key-remove", function(keyidstr) {
    var keys = ppgapp.removeKey(keyidstr);
    worker.port.emit("pgp-key-removed", keyidstr);
  });
  worker.port.on("pgp-msg-decrypt", function(params) {
    var res = {rc: 0, ts: params.ts};
    ppgapp.decrypt(params.msg, function(err, decmsg, enc_keyid) {
      res.enc_keyid = enc_keyid;
      if (err) {
        res.rc = -1;
        res.msg = err.toString();
      } else {
        res.rc = decmsg.type; 
        res.msg = decmsg.msg; 
        res.sign_keyid = decmsg.sign_keyid;
        if (decmsg.type == 1) {
          var key = ppgapp.findKey(decmsg.sign_keyid);
          if (key)
            res.sign_key_uid = key.uids[0].name;
        }
      }
      worker.port.emit("pgp-msg-decrypted", res);
    });
  });
  worker.port.on("pgp-msg-encrypt", function(params) {
    var res = {rc: 0, ts: params.ts, enc_keyid: params.enc_keyid, sign_keyid: params.sign_keyid};
    ppgapp.encrypt(params.msg, [params.enc_keyid], params.sign_keyid, function(err, msg) {
      if (err) {
        res.rc = -1;
        res.msg = err.toString();
      } else {
        res.msg = msg;
      }
      worker.port.emit("pgp-msg-encrypted", res);
    });
  });
  worker.port.on("pgp-msg-sign", function(params) {
    var res = {rc: 0, ts: params.ts, sig: params.keyid};
    ppgapp.sign(params.msg, params.keyid, function(err, msg) {
      if (err) {
        res.rc = -1;
        res.msg = err.toString();
      } else {
        res.msg = msg;
      }
      worker.port.emit("pgp-msg-signed", res);
    });
  });
  worker.port.on("pgp-msg-verify", function(params) {
    var res = {rc: 0, ts: params.ts};
    ppgapp.verify(params.msg, function(err, valid, keyid) {
      if (err) {
        if (err.toString() == "PGP.ERR.NOT_FOUND") {
          res.rc = 1;
          res.issuerid = keyid;
        } else
          res.rc = -1;
        res.valid = false;
      } else {
        res.issuerid = keyid;
        res.valid = valid;
      }
      worker.port.emit("pgp-msg-verified", res);
    });
  });
  worker.port.on("pgp-search-publickey", function(text) {
    var results = storage.search(text);
    worker.port.emit("pgp-search-publickey-results", results);
  });
  worker.port.on("pgp-fetch-keyring", function() {
    var keys = storage.getAllKeys();
    worker.port.emit("pgp-fetched-keyring", keys);
  });
  worker.port.on("pgp-fetch-public-keys", function() {
    var keys = storage.getPublicKeys();
    worker.port.emit("pgp-fetched-public-keys", keys);
  });
  worker.port.on("pgp-fetch-all-keys", function() {
    var keys = storage.getAllKeys();
    worker.port.emit("pgp-fetched-all-keys", keys);
  });
  worker.port.on("pgp-fetch-private-keys", function() {
    var keys = storage.getPrivateKeys();
    worker.port.emit("pgp-fetched-private-keys",  { "keys": keys, "default_key_id": storage.getDefault() });
  });
  worker.port.on("pgp-options-fetch-keys", function() {
    worker.port.emit("pgp-options-fetched-keys", { "keys": storage.getPrivateKeys(), "default_key_id": storage.getDefault() });
  });
  worker.port.on("pgp-keyring-delete-subkey", function (subkeyid) {
    var res = {rc: 0, msg: "", subkeyid: subkeyid};
    var key = ppgapp.findKey(subkeyid)
    var removed = ppgapp.removeSubkey(keyid, subkey_num)
    if (removed) {
      res.msg = "Subkey " + subkeyid + "removed!";
      res.subkeyid = subkeyid;
    } else {
      res.rc = -1;
      res.msg = "Couldn't remove subkey " + subkeyid + "";
    }
    worker.port.emit("pgp-keyring-deleted-subkey", res);
  });
  worker.port.on("pgp-keyring-delete-uid", function (keyid, uid_num) {
    var res = {rc: 0, msg: "", keyid: keyid, uid_num: uid_num};
    if (ppgapp.removeUserId(keyid, uid_num)) {
      res.msg = "Uid[" + uid_num + "] removed!";
    } else {
      res.rc = -1;
      res.msg = "Couldn't remove uid[" + uid_num + "]";
    }
    worker.port.emit("pgp-keyring-deleted-uid", res);
  });
  worker.port.on("pgp-keyring-delete-keys", function (keys) {
    var deleted_keys = [];
    var not_deleted_keys = [];
    for (var i=0; i < keys.length; i++) {
      if (ppgapp.removeKey(keys[i])) {
        deleted_keys.push(keys[i]);
      } else
        not_deleted_keys.push(keys[i]);
    }
    var response = { rc: deleted_keys.length == keys.length ? 0 : -1,
      deleted_keys: deleted_keys,
      not_deleted_keys: not_deleted_keys,
    }
    worker.port.emit("pgp-keyring-deleted-keys", response);
  });
  worker.port.on("pgp-keyring-delete-all-keys", function () {
    var num_keys = ppgapp.removeAllKeys();
    worker.port.emit("pgp-keyring-deleted-all-keys", num_keys);
  });
}

var mainworker = null;
var maintab = null;

function openapp(secname) {
  tabs.open({
    url     : data.url("ui/main.html#" + secname),
    onReady : function(tab) {
      apptab = tab;
      var worker = tab.attach({
        contentScript: sectionsContentScripts(),
        contentScriptFile: [ data.url("ui/ejs_production.js"),
                             data.url("ui/ppg-lib.js"),
                             data.url("ui/genkey.js"),
                             data.url("ui/import_keys.js"),
                             data.url("ui/encrypt.js"),
                             data.url("ui/decrypt.js"),
                             data.url("ui/sign.js"),
                             data.url("ui/verify.js"),
                             data.url("ui/options.js"),
                             data.url("ui/export_selected.js"),
                             data.url("ui/search_keys.js"),
                             data.url("ui/welcome.js"),
                             data.url("ui/manager.js"),
                             data.url('ui/views/box.js'),
                             data.url('ui/views/boxes.js'),
                             data.url('ui/views/keylist_view.js'),
                             data.url('ui/views/key_view.js'),
                             data.url('ui/views/key_subkey_view.js'),
                             data.url('ui/views/key_uid_view.js'),
                             data.url('ui/views/key_uidsig_view.js'),
                             data.url('ui/views/hkpkey_view.js'),
                             data.url('ui/sprintf.js'),
                             data.url('ui/tabs.js'),
                             data.url('ui/dialogs.js'),
                             data.url('ui/keyring.js'),
                             data.url("ui/main.js") ],
        contentURL: data.url('graphics/lock.png'),
      });

      load_events(worker);
      maintab = tab;
      mainworker = worker;
    }
  });
}

var ppgapp_panel = require("panel").Panel({
  width: 250,
  height: 250,
  contentURL: data.url("ui/panel.html"),
  contentScript: (function() { 
        var options = storage.get_all_options();
        return "\nPanel.init( " + JSON.stringify(options) + ");";
  })(),
  contentScriptFile: [data.url("ui/ejs_production.js"),
                      data.url("ui/ppg-lib.js"),
                      data.url("ui/panel.js")],
});

var widget = widgets.Widget({
  id: "ppgapp-link",
  label: "PidgeonPG Website",
  contentURL: data.url('graphics/logo.ico'),
  panel: ppgapp_panel
});

ppgapp_panel.port.on("open-section", function(name) {
  if (maintab) 
    for each(var tab in tabs) 
      if (tab == maintab) {
        mainworker.port.emit("open-section", name);
        tab.activate();
        return;
      }
  openapp(name);
});

openapp("");

exports.main = function(options, callbacks) {
  // If you run cfx with --static-args='{"quitWhenDone":true}' this program
  // will automatically quit Firefox when it's done.
//  if (options.staticArgs.quitWhenDone)
//    callbacks.quit();
};


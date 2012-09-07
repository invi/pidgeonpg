const {Cu, Ci, Cc, components} = require("chrome");
const {getStr} = require("util/lang");

var {XPCOMUtils} = Cu.import("resource://gre/modules/XPCOMUtils.jsm");
XPCOMUtils.defineLazyServiceGetter(this, "promptSvc",
                                   "@mozilla.org/embedcomp/prompt-service;1",
                                   "nsIPromptService");

var STD_OK_CANCEL_BUTTONS = 513;
var BUTTON_TITLE_OK = 1;

var prompt = {
  newPassphrase: function() {
    let passphrase1 = {};
    let passphrase2 = {};
    while(1) {
      var prompt1 = promptSvc.promptPassword(null,
                               getStr("enterPassphraseTitle"),
                               getStr("enterPassphraseText"),
                               passphrase1, null, {value: false});
      if (!prompt1) throw Error("passwordEnterCancelled");
      var prompt2 = promptSvc.promptPassword(null,
                               getStr("confirmPassphraseTitle"),
                               getStr("confirmPassphraseText"),
                               passphrase2, null, {value: false});
      if (!prompt2) throw Error("passwordEnterCancelled");
      if (passphrase1.value != passphrase2.value) 
        this.alert(getStr("passphrasesDoNotMatchTitle"), getStr("passphrasesDoNotMatchText"));
      else if (passphrase1.value == "") {
        if (this.confirm(getStr("noPassphraseEntered"), getStr("continueWithoutPassword")))
          break;
      } else
        break;
    }
    return {passphrase: passphrase1.value};
  },
  enterPassphrase: function() {
    let passphrase = {};
    let prompt =
      promptSvc.promptPassword(null,
                               getStr("enterPassphraseTitle"),
                               getStr("enterPassphraseText"),
                               passphrase, null, {value: false});
    if (prompt && passphrase.value) 
      return passphrase.value;
    else
      throw Error("enterPasswordCancelled");
  },
  alert: function(title, text) {
    promptSvc.alert(null, title, text);
  },
  confirm: function(title, text) {
    return  promptSvc.confirmEx(null,
                                title,
                                text,
                                STD_OK_CANCEL_BUTTONS, 
                                null, 
                                null,
                                null,
                                null,
                                {value:false})
  }
}

exports.prompt = prompt;

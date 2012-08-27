
var RoundCube = {
  dataurl: "",
  cbody: undefined,
  extract_emails: function(emailsStr) {
    return emailsStr.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi);
  },
  compose: function() {
    var self = this;
    this.cbody.style.display = "none";
    var to_ele = document.getElementById("_to");
    var submit_ele = ELE("rcmbtn110");
    var framed_cbody = document.createElement("iframe");
    this.cbody.parentNode.insertBefore(framed_cbody, this.cbody);
    framed_cbody.src = "";
    framed_cbody.contentWindow.location.href = this.dataurl + "ui/textarea.xml";
    //framed_cbody.contentDocument.body.innerHTML = "";
    framed_cbody.style.width = "100%";
    framed_cbody.style.height = "100%";
    framed_cbody.style.border = "none";
    
    var onclick_action = 
      "var res = document.getElementById('PidgeonPG');" +
      "var handler = null;" + 
      "function check_end() {" + 
      "  if (res.innerHTML=='true') {" +
      "    clearInterval(handler);" +
          submit_ele.getAttribute("onclick") + 
      "  }" +
      "};" + 
      "handler = setInterval(check_end, 500);";
    

    submit_ele.setAttribute("onclick", onclick_action);
    submit_ele.addEventListener("click", function() {
      try {
        ONCE("pgp-msg-encrypted", function(res) {
          framed_cbody.style.display = "none";
          self.cbody.style.display = "";
          self.cbody.value = res.msg;
          document.getElementById('PidgeonPG').innerHTML = 'true';
        });
        var fcbody = framed_cbody.contentWindow.document.getElementById("body-toencrypt");
        var req = {
          ts: Date.now(),
          enc_keyid: "3F653F60F7637CD3", 
          enc_emails: self.extract_emails(to_ele.value), 
          sign_keyid: null, 
          msg: fcbody.value,
        }
        EMIT("pgp-msg-encrypt", req);
      } catch(e) { log_error(e); }
    });
    var res = document.createElement("div");
    res.id = "PidgeonPG";
    res.innerHTML = "false";
    res.style.display = "none";
    document.body.appendChild(res);
  },
  init: function(dataurl) {
    this.dataurl = dataurl;
    var rcstart=document.body.getAttribute("onload") == "rcube_init_mail_ui()";
    if (rcstart) {
      console.log("RoundCube detected");
      this.cbody = ELE("compose-body");
      if (this.cbody) this.compose();
      else this.findBlocks();
    }
  },
  findBlocks: function() {
    FireGPG.Inline.HandlePage(document, this.dataurl);
  }
}


/*

***** BEGIN LICENSE BLOCK *****

Version: MPL 1.1/GPL 2.0/LGPL 2.1

The contents of this source code are subject to the Mozilla Public License
Version 1.1 (the "License"); you may not use this source code except in
compliance with the License. You may obtain a copy of the License at
http://www.mozilla.org/MPL/

Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
for the specific language governing rights and limitations under the
License.

The Original Code is the FireGPG extension.

The Initial Developer of this part of the Original Code is Ryan Patterson.

Portions created by the Initial Developer are Copyright (C) 2007
the Initial Developer. All Rights Reserved.

Contributor(s): Maximilien Cuony

Alternatively, the contents of this source code may be used under the terms of
either the GNU General Public License Version 2 or later (the "GPL"), or
the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
in which case the provisions of the GPL or the LGPL are applicable instead
of those above. If you wish to allow use of your version of this source code
only under the terms of either the GPL or the LGPL, and not to allow others to
use your version of this source code under the terms of the MPL, indicate your
decision by deleting the provisions above and replace them with the notice
and other provisions required by the GPL or the LGPL. If you do not delete
the provisions above, a recipient may use your version of this source code
under the terms of any one of the MPL, the GPL or the LGPL.

***** END LICENSE BLOCK *****

*/
FireGPG = { };
FireGPG.Inline = { };

/*
   Constants: Tags of PGP's blocks

   FireGPG.Inline.Tags.PgpBlockStart - Start of a PGP block
   FireGPG.Inline.Tags.KeyStart - Start of a PGP key
   FireGPG.Inline.Tags.KeyEnd - End of a PGP key
   FireGPG.Inline.Tags.PrivateKeyStart - Start of a PGP private key
   FireGPG.Inline.Tags.PrivateKeyEnd - End of a PGP private key
   FireGPG.Inline.Tags.SignedMessageStart - Start of a signed message
   FireGPG.Inline.Tags.SignatureStart - Start of a sign
   FireGPG.Inline.Tags.SignatureEnd - End of a sign
   FireGPG.Inline.Tags.EncryptedMessageStart - Start of an encrypted message
   FireGPG.Inline.Tags.EncryptedMessageEnd - End of an encrypted message

*/
FireGPG.Inline.Tags = {
    PgpBlockStart: "-----BEGIN PGP",
	KeyStart: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
	KeyEnd: "-----END PGP PUBLIC KEY BLOCK-----",
	PrivateKeyStart: "-----BEGIN PGP PRIVATE KEY BLOCK-----",
	PrivateKeyEnd: "-----END PGP PRIVATE KEY BLOCK-----",
	SignedMessageStart: "-----BEGIN PGP SIGNED MESSAGE-----",
	SignatureStart: "-----BEGIN PGP SIGNATURE-----",
	SignatureEnd: "-----END PGP SIGNATURE-----",
	EncryptedMessageStart: "-----BEGIN PGP MESSAGE-----",
	EncryptedMessageEnd: "-----END PGP MESSAGE-----",
};

/*
   Constants: Types of blocks

   FireGPG.Inline.KEY_BLOCK - It's a key block
   FireGPG.Inline.PRIVATE_KEY_BLOCK - It's a private key block
   FireGPG.Inline.SIGN_BLOCK    - It's a sign block
   FireGPG.Inline.MESSAGE_BLOCK   - It's a message block
*/

FireGPG.Inline.KEY_BLOCK = 1;
FireGPG.Inline.PRIVATE_KEY_BLOCK = 2;
FireGPG.Inline.SIGN_BLOCK = 3;
FireGPG.Inline.MESSAGE_BLOCK = 4;

/*
    Function: HandleBlock
    This function build a secure iframe for a PGP's block, and add listeners for actions on this block

    Parameters:
        document - The current document
        range - A range with the PGP  block selected
        blockType - The type of block, see <Types of blocs>
*/
FireGPG.Inline.HandleBlock = function(document, range, blockType, dataurl) {

    var i18n = document.getElementById("firegpg-strings");

	// Get content, remove whitespace from beginning of the lines.

    var s = new XMLSerializer();
	var d = range.cloneContents();
	var str = s.serializeToString(d);

    var content = FireGPG.Selection.wash(str);

    var fragment = range.extractContents();

	// We use an iframe to prevent the owning page from accessing potentially
	// private information (contents of encrypted message).
	var frame = document.createElement("iframe");
	range.insertNode(frame);
	frame.contentWindow.location.href = dataurl + "ui/block.xml";
	frame.style.border = "none";
	frame.style.width = "100%";
	frame.style.height = "100%";
	frame.addEventListener("load", function() {
    try {
		  var block = {
        frame: frame,
		  	body: frame.contentDocument.getElementsByTagName("body")[0],
		  	header: frame.contentDocument.getElementById("header"),
		  	output: frame.contentDocument.getElementById("output"),
		  	message: frame.contentDocument.getElementById("message"),
		  	action: frame.contentDocument.getElementById("action"),
		  	original: frame.contentDocument.getElementById("original")
		  }

          frame.contentDocument.getElementById("toggle-original").textContent = FireGPG.Inline.i18n.getString("show-original")

		  // Universal set up
		  block.original.textContent = content;

          frame.contentDocument.getElementById("toggle-original").addEventListener("click", function() {
		  	var style = block.original.style;
		  	if(style.display == "block") {
		  		style.display = "none";
                  this.textContent = FireGPG.Inline.i18n.getString("show-original");
              }
		  	else {
		  		style.display = "block";
                  this.textContent = FireGPG.Inline.i18n.getString("hide-original");
              }
              frame.style.width = block.body.scrollWidth + "px";
		  	frame.style.height = block.body.scrollHeight + "px";
		  }, false);


          frame.contentDocument.getElementById("switch-direction").textContent = FireGPG.Inline.i18n.getString("switchdirection")
          frame.contentDocument.getElementById("switch-direction").addEventListener("click", function() {
		  	var style = block.original.style;
		  	if(style.direction == "rtl") {
		  		style.direction = "ltr";
                  block.message.style.direction = "ltr";
              }
		  	else {
		  		style.direction = "rtl";
                  block.message.style.direction = "rtl";
              }

		  }, false);


		  var actionHandler = function() {
		  	switch(blockType) {
		  		case FireGPG.Inline.KEY_BLOCK:
		  			FireGPG.Inline.ImportKey(block.original.textContent, block);
		  			break;
		  		case FireGPG.Inline.PRIVATE_KEY_BLOCK:
		  			block.body.className = "failure";
                      block.output.style.display = "block";
                      block.output.textContent = FireGPG.Inline.i18n.getString("private-key-block-message").replace(/\. /g, ".\n");
		  			break;
		  		case FireGPG.Inline.SIGN_BLOCK:
		  			FireGPG.Inline.VerifySignature(block.original.textContent, block);
		  			break;
		  		case FireGPG.Inline.MESSAGE_BLOCK:
		  			FireGPG.Inline.DecryptMessage(block.original.textContent, block);
		  			break;
		  	}
              frame.style.width = block.body.scrollWidth + "px";
		  	frame.style.height = block.body.scrollHeight + "px";

		  };
		  block.action.addEventListener("click", actionHandler, false);

		  switch(blockType) {
		  	case FireGPG.Inline.KEY_BLOCK:
		  		block.body.className = "information";
		  		block.header.textContent = FireGPG.Inline.i18n.getString("key-block");
		  		block.action.textContent = FireGPG.Inline.i18n.getString("import");
		  		break;
		  	case FireGPG.Inline.PRIVATE_KEY_BLOCK:
		  		block.body.className = "information";
		  		block.header.textContent = FireGPG.Inline.i18n.getString("private-key-block");
		  		block.action.textContent = FireGPG.Inline.i18n.getString("import");
		  		break;
		  	case FireGPG.Inline.SIGN_BLOCK:
		  		block.body.className = "caution";
		  		block.header.textContent = FireGPG.Inline.i18n.getString("signed-message")  + ", " + FireGPG.Inline.i18n.getString("unverified");
		  		block.action.textContent = FireGPG.Inline.i18n.getString("verify");
		  		// Extract the message without the header and signature
		  		block.message.innerHTML = escapeHTML(content.substring(content.indexOf("\n\n") + 2, content.indexOf(FireGPG.Inline.Tags.SignatureStart)).replace(/</gi,"&lt;").replace(/>/gi,"&gt;").replace(/\n/gi,"<br />"));
		  		break;
		  	case FireGPG.Inline.MESSAGE_BLOCK:
		  		block.body.className = "caution";
		  		block.header.textContent = FireGPG.Inline.i18n.getString("encrypted-message") ;
		  		block.action.textContent = FireGPG.Inline.i18n.getString("decrypt");
		  		break;
		  }

		  // Make sure that the block has nonzero size before resizing the frame:
		  frame.resize = function(self, content) {
		      if(content.body.scrollWidth != 0 && content.body.scrollHeight != 0) {

                  if (content.body.scrollWidth > 50)
                      width = content.body.scrollWidth;
                  else
                      width = 50;

                   if (content.body.scrollHeight > 50)
                      height = content.body.scrollHeight;
                  else
                      height = 50;

                  self.style.width = width + "px";
                  self.style.height = height + "px";
		      } else {
		  	// Wait 100ms and try again:
                  self.try += 1;
                  if (self.try < 20)
                      setTimeout(self.resize, 100, self, content);
		      }
		  }

       frame.try = 0;
    	 frame.resize(frame, block);

    } catch(e) { log_error(e); }

	}, false);
};

/*
    Function: HandlePage
    This function parse a page to find PGP's block.

    Parameters:
        document - The current document

*/
FireGPG.Inline.HandlePage = function(document, dataurl) {

	var filter = function(node) {
		return NodeFilter.FILTER_ACCEPT;
	};

	var haveStart = false;
	var blockType;
	var tw = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT, filter, false);
	var node, range, idx, search, baseIdx;
	while((node = tw.nextNode())) {
		idx = 0;
		while(true) {
			if(!haveStart) {

                if (node.textContent.indexOf(FireGPG.Inline.Tags.PgpBlockStart, idx) == -1)
                    break;

                if (node.parentNode && node.parentNode.nodeName == 'TEXTAREA')
                    break;


                if (node.parentNode && node.parentNode.nodeName == 'PRE' && node.parentNode.parentNode && node.parentNode.parentNode.parentNode  && typeof node.parentNode.parentNode.parentNode.getAttribute == 'function' && node.parentNode.parentNode.parentNode.getAttribute('id') == 'storeArea') {
                    //Hum, it's seem we're on a TidyWiki...

                    var topwinjs = node.ownerDocument.defaultView.parent.wrappedJSObject;
                    if ("version" in topwinjs && topwinjs.version.title == "TiddlyWiki")
                        break; //We are, so we stop
                }

                baseIdx = idx;
				idx = node.textContent.indexOf(FireGPG.Inline.Tags.KeyStart, baseIdx);
                blockType = FireGPG.Inline.KEY_BLOCK;
				search = FireGPG.Inline.Tags.KeyEnd;
				if(idx == -1   || idx < node.textContent.indexOf(FireGPG.Inline.Tags.SignedMessageStart, baseIdx)) {
					idx = node.textContent.indexOf(FireGPG.Inline.Tags.SignedMessageStart, baseIdx);
					search = FireGPG.Inline.Tags.SignatureEnd;
                    blockType = FireGPG.Inline.SIGN_BLOCK;
				}
				if(idx == -1 || idx < node.textContent.indexOf(FireGPG.Inline.Tags.EncryptedMessageStart, baseIdx)) {
					idx = node.textContent.indexOf(FireGPG.Inline.Tags.EncryptedMessageStart, baseIdx);
					search = FireGPG.Inline.Tags.EncryptedMessageEnd;
                    blockType = FireGPG.Inline.MESSAGE_BLOCK;
				}
				if(idx == -1 || idx < node.textContent.indexOf(FireGPG.Inline.Tags.PrivateKeyStart, baseIdx)) {
					idx = node.textContent.indexOf(FireGPG.Inline.Tags.PrivateKeyStart, baseIdx);
					blockType = FireGPG.Inline.PRIVATE_KEY_BLOCK;
					search = FireGPG.Inline.Tags.PrivateKeyEnd;
				}

				if(idx == -1)
          break;

				haveStart = true;
				range = document.createRange();
				range.setStart(node, idx);
				idx += 6;
			}
			if(haveStart) {

          tryOne = node.textContent.indexOf(search, idx);

                if(tryOne == -1)
					break;

				idx = node.textContent.indexOf(search, this.ignoreInners(idx,tryOne,node.textContent));

                if(idx == -1) {
					break;
				}

        haveStart = false;

				range.setEnd(node, idx + search.length);
				FireGPG.Inline.HandleBlock(document, range, blockType, dataurl);
				range.detach();
				idx =0; //+= search.length;
			}
		}
	}
};

/*
    Function: ignoreInners
    This is a function for .<HandlePage>, who try to avoid detection of PGP block into PGP blocks

    Parameters:
        idx - The current position of the block detection
        end - The last position of the block detected
        node - The node where we works

*/
FireGPG.Inline.ignoreInners = function(idx, end,node) {

        if  (end == -1)
            return -1;

        var baseIdx = idx;

        idx = node.indexOf(FireGPG.Inline.Tags.KeyStart, baseIdx);
        search = FireGPG.Inline.Tags.KeyEnd;

        if(idx == -1) {
            idx = node.indexOf(FireGPG.Inline.Tags.SignedMessageStart, baseIdx);
            search = FireGPG.Inline.Tags.SignatureEnd;
        }
        if(idx == -1) {
            idx = node.indexOf(FireGPG.Inline.Tags.EncryptedMessageStart, baseIdx);
            search = FireGPG.Inline.Tags.EncryptedMessageEnd;
        }
        if(idx == -1) {
            idx = node.indexOf(FireGPG.Inline.Tags.PrivateKeyStart, baseIdx);
            search = FireGPG.Inline.Tags.PrivateKeyEnd;
        }

        if(idx == -1 || idx > end)
            return end;

        return node.indexOf(search,
                this.ignoreInners(idx + 6,node.indexOf(search,idx + 6),node)
                ) + 6;


}

/*
    Function: ImportKey
    This is the function called when the user click on "Import" for a PGP's key block

    Parameters:
        content - The PGP data.
        block - The block who contain the iframe

*/
FireGPG.Inline.ImportKey = function(content, block) {
  ONCE("pgp-keyblock-parsed", function(res) {
    try {
	     block.output.style.display = "block";
       for (var i=0;i<res.keys.length;i++) {
         var li_ele = block.frame.contentDocument.createElement("li");
         block.output.appendChild(li_ele);
       }
	     if(res.rc == 0)
	     	block.body.className = "ok";
	     else
	     	block.body.className = "failure";
    } catch(e) { 
      log_error(e);
    }
  });
  EMIT("pgp-key-parse", "text", Date.now(), null, content);
};

/*
    Function: VerifySignature
    This is the function called when the user click on "Verify" for a PGP's signed message block

    Parameters:
        content - The PGP data.
        block - The block who contain the iframe

*/
FireGPG.Inline.VerifySignature = function(content, block) {

    var i18n = document.getElementById("firegpg-strings");

    ONCE("pgp-msg-verified", function(res) {
      resultTest = res.rc

      if (resultTest.signresult == FireGPG.Const.Results.SUCCESS) {
          block.body.className = "ok";
          block.header.textContent = i18n.getString("signed-message") + ", " + resultTest.signsresulttext;
      }
      else if (resultTest.signresult == FireGPG.Const.Results.ERROR_BAD_SIGN) {
          block.body.className = "failure";
          block.header.textContent = i18n.getString("signed-message") + ", " + i18n.getString("verifFailedFalse");
      }
      else if (resultTest.signresult == FireGPG.Const.Results.ERROR_NO_KEY) {
          block.body.className = "failure";
          block.header.textContent = i18n.getString("signed-message") + ", " + i18n.getString("verifFailedUnknownKey") ;
      }
      else {
          block.body.className = "failure";
          block.header.textContent = i18n.getString("signed-message") + ", " +i18n.getString("verifFailedGeneral");
      }
    });
    EMIT("pgp-msg-verify", { ts: Date.now(), msg: content });
};

/*
    Function: DecryptMessage
    This is the function called when the user click on "Decrypt" for a PGP's encrypted message block

    Parameters:
        content - The PGP data.
        block - The block who contain the iframe

*/
FireGPG.Inline.DecryptMessage = function(content, block) {
  try {
    ONCE("pgp-msg-decrypted", function(res) {
      if (res.rc == 0) {
          block.body.className = "ok";
          block.message.textContent = res.msg;
      } else {
          block.body.className = "failure";
          block.output.style.display = "block";
          block.output.textContent = res.msg;
      }
    });
    EMIT("pgp-msg-decrypt", {ts: Date.now(), msg: content});
  } catch(err) { callback(err); }
};

FireGPG.Inline.i18n = {};
FireGPG.Inline.i18n.getString = getStr;

FireGPG.Core = {};

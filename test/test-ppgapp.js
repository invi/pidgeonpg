// # Test: ppgapp
// 
// <!--name=ppgappapptest-->
// 
// Tests for ppgapp application interface 


const PGP = require("pgp/openpgpdefs");
const {ppgapp} = require('ppgapp');
const {storage} = require('ring/storage');
const {parsekeysfile} = require("pgp/key-parse");
const logger = require("util/logger").create("test-ppgapp.js");
const timers = require("timers");

var {prompt} = require("util/prompt");
prompt.newPassphrase = function() { return { passphrase: "1234" } };
prompt.enterPassphrase = function() { return "1234" };

var test_key = "test/key1.asc";
var test_key2 = "test/key2.asc";
var msg_txt = "Hello world";


exports.testImportFile = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    test.assertEqual(imported_keys[0].ringstatus, PGP.KEYSTATUS.NEW, 
                    "Error importing new key file");
    test.done();
  });
}

exports.testSignUId = function(test) {
  storage.cleantest();
	test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    ppgapp.setDefaultKeyId(imported_keys[0].id);
    ppgapp.importFile(test_key2, function(imported_keys2) {
      var keytosign = imported_keys2[0];
      ppgapp.signUserId(keytosign.id, 0, function(err, key) {
        if (err) logger.error(err);
        test.assertEqual(key.uids[0].sigs.length, 1,"Uid sig not added");
	      test.done();
      });
    });
  });
}

exports.testCreateUId = function(test) {
  storage.cleantest();
	test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    var key = imported_keys[0];
    var expiredate = Math.floor(new Date("10/10/2030").getTime() / 1000);
    var options = {name: "test new uid <abc@ppgapp.org>", expireseconds: 0};
    ppgapp.generateUserId(key.id, options, function(err, key, uid) {
      if (err) logger.error(err);
      test.assertEqual(uid.name, "test new uid <abc@ppgapp.org>", "New uid name mismatch");
	    test.done();
    });
  });
}

exports.testCreateSubkey = function(test) {
  storage.cleantest();
	test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    try {
      var key = imported_keys[0];
      var expiredate = Math.floor(new Date("10/10/2030").getTime() / 1000);
      var options = { 
        keypairBits: 1024,
        keyType: PGP.PUBKEY.ALGO.RSA,
        subkeyType: PGP.PUBKEY.ALGO.RSA,
        expireseconds: 0,
      }
      ppgapp.generateSubkey(key.id, options, function(err, key, subkey) {
        if (err) logger.error(err);
        test.assertEqual(subkey.algo, "RSA", "New uid name mismatch");
	      test.done();
      });
    } catch(err) { logger.error(err) }
  });
}

exports.testGenerate = function(test) {
  storage.cleantest();
  test.waitUntilDone(60000);
  var options = { 
    expiredate : Math.floor(new Date("10/10/2030").getTime() / 1000),
    name       : "test name",
    comment    : "test comment",
    email      : "test@ppgapp.org",
    passphrase : "asdf",
    keypairBits : 1024,
    keyType     : PGP.PUBKEY.ALGO.RSA,
    subkeyType  : PGP.PUBKEY.ALGO.RSA,
  }
  try {
  ppgapp.generateKeypair(options, function(err, key) {
    if (err) logger.error(err);
    test.assertEqual(key.ringstatus, PGP.KEYSTATUS.NEW, 
                     "Error importing new  key string");
    test.done();
  });
  } catch(err) {console.log(err)}
}

exports.testRevokeKey = function(test) {
  storage.cleantest();
	test.waitUntilDone();

  ppgapp.importFile(test_key, function(imported_keys) { 
    var key = imported_keys[0];
    //Reason 1: Key is superseded
    ppgapp.revokeKey(key.id, 1, "Test for revocation", function(err, key) {
      if (err) logger.error(err);
      test.assertEqual(key.revoked, true, "Incorrect revocation");
	    test.done();
    });
  });
}

exports.testRevokeSubkey = function(test) {
  storage.cleantest();
	test.waitUntilDone();

  ppgapp.importFile(test_key, function(imported_keys) { 
    var key = imported_keys[0];
    //Reason 1: Key is superseded
    ppgapp.revokeSubkey(
      key.subkeys[0].id, 1, "Test subkey rev", function(err, key) {
        if (err) logger.error(err);
        test.assertEqual(key.subkeys[0].revoked, true, 
                         "Incorrect revocation");
        test.done();
      });
  });
}

exports.testRevokeUserId = function(test) {
  storage.cleantest();
	test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    var key = imported_keys[0];
    ppgapp.revokeUserId(key.id, 0, 0, "finito", function(err, key) {
      if (err) logger.error(err);
      test.assertEqual(key.uids[0].revoked, true, "Incorrect revocation");
      test.done();
    })
  });
}

exports.testSignVerify = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    var key = imported_keys[0];
    ppgapp.sign(msg_txt, key.id, function(err, signedmsg) {
      if (err) logger.error(err);
      ppgapp.verify(signedmsg, function(err, isValid) {
        if (err) logger.error(err);
        test.assertEqual(isValid, true, "Invalid signature");
        test.done();
      });
    });
  });
}

exports.testEncryptDecrypt = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    var key = imported_keys[0];
    ppgapp.encrypt(msg_txt, ["example1@webpg.org"], null, function(err, encmsg) {
      if (err) logger.error(err);
      ppgapp.decrypt(encmsg, function(err, decmsg) {
        if (err) logger.error(err);
        test.assertEqual(msg_txt, decmsg.msg, "Encrypt/Decrypt interface fails");
        test.done();
      });
    });
  });
}

exports.testRemoveKey = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    var key = imported_keys[0];
    ppgapp.removeKey(key.id);
    test.assertEqual(storage.find(key.id), false, "Key not removed from local ring");
    test.done();
  });
}

exports.testRemoveSubkey = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    var key = imported_keys[0];
    var updated_key = ppgapp.removeSubkey(key.subkeys[0].id);
    test.assertEqual(updated_key.subkeys.length, 0, "Uid not removed from local ring");
    test.done();
  });
}

exports.testGetPublicKeys = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    // Since we are importing a Secret key, we expect 0 public keys
    var key_list = ppgapp.getPublicKeys();
    test.assertEqual(key_list.length, 0, "Unexpected count of public keys");
    test.done();
  });
}

exports.testUpdateUid = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    // Since we are importing a Secret key, we expect 0 public keys
    var key = imported_keys[0];
    var d = key.uids[0].selfsigs[0].creation_date.split("/");
    var ts = Math.floor(new Date(d[1]+"/"+d[0]+"/"+d[2]).getTime()/1000);
    ppgapp.editUserId(key.id, 0,  3600*24*30, function(err, key, uid) { 
      var d = key.uids[0].selfsigs[0].creation_date.split("/");
      var ts2 = Math.floor(new Date(d[1]+"/"+d[0]+"/"+d[2]).getTime()/1000);

      test.assertEqual(ts < ts2, true, "Uid self-signature timestamp update");
      test.done();
    });
  });
}


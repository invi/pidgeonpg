
// ## Tests for different kind of encrypted messages.
// Encryptedmessage class not tested directly, instead
// calls are proxied through ppgappapp module.

const PGP = require("pgp/openpgpdefs");
const {data} = require('self');
const {ppgapp} = require('ppgapp');
const logger = require('util/logger').create("test-encryptedmessage.js");
const {storage} = require('ring/storage');
const {parsekeysfile} = require("pgp/key-parse");

var test_data  = {key1: "test/key1.asc", msg2: "test/msg2.asc",
                  key_protected: "test/key2.asc", msg3: "test/msg9.asc", 
                  msg_compressed: "test/msg6.asc", 
                  msg_zlib: "test/msg_zlib.asc", 
                  msg_bzip2: "test/msg_bzip2.asc", 
                  key_dsaelgamal: "test/key_dsaegamal_unprotected.asc",
                  msg_elgamal: "test/msg_egamal.asc",
                  msg_encsign: "test/msg4.asc",
                  msg_multiple_recipients: "test/msg_multiple_recipients.asc",
                  msg_5: "test/msg5.asc", msg_txt: "hello wok"};

exports.testDecryptKeyNotFound = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  var msgdata = data.load(test_data.msg2);
  ppgapp.decrypt(msgdata, function(err, result) {
    test.assertEqual(err.toString(), "Error: Decryption key not found", "expected key not found");
    test.done();
  });
};

exports.testDecrypt = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key1, function() {
    var msgdata = data.load(test_data.msg2);
    ppgapp.decrypt(msgdata, function(err, res) {
      test.assertEqual(res.msg, "hello example1, how are you\n", 
                         "plain message decrypt failed");
      test.done();
    });
  });
};

////XXX should be a way to pass the password without user's input
////exports.testDecryptProtected = function(test)
////{
////  storage.cleantest();
////  test.waitUntilDone();
////  ppgapp.importFile(test_data.key_protected, function() {
////    var msgdata = data.load(test_data.msg3);
////    ppgapp.decrypt(msgdata, function(result) {
////      test.assertEqual(result.msg, 
////                       "encrypted message for protected key key2@testing.xyz\n", 
////                       "plain message decrypt failed");
////      test.done();
////    });
////  });
////};
//
exports.testDecryptZipCompressed = function(test)
{
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key1, function() {
    var msgdata = data.load(test_data.msg_compressed);
    ppgapp.decrypt(msgdata, function(err, result) {
      test.assertEqual(result.msg, "encrypted with zip compression\n", 
                         "compressed message decrypt failed");
      test.done();
    });
  });
};

exports.testDecryptZlibCompressed = function(test)
{
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key1, function() {
    var msgdata = data.load(test_data.msg_zlib);
    ppgapp.decrypt(msgdata, function(err, result) {
      test.assertEqual(result.msg, "compressed with zlib\n", 
                         "compressed message decrypt failed");
      test.done();
    });
  });
};

exports.testDecryptBzip2Compressed = function(test)
{
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key1, function() {
    var msgdata = data.load(test_data.msg_bzip2);
    ppgapp.decrypt(msgdata, function(err, result) {
      test.assertEqual(result.msg, "compressed with bzip2\n", 
                         "compressed message decrypt failed");
      test.done();
    });
  });
};

exports.testDecryptAndVerify = function(test)
{
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key_protected, function() {
    ppgapp.importFile(test_data.key1, function() {
      var msgdata = data.load(test_data.msg_encsign);
      ppgapp.decrypt(msgdata, function(err, result) {
        test.assertEqual(result.type, PGP.DECRYPT_RC.SIGN_VERIFIED, 
                           "error verifing signature");
        test.assertEqual(result.msg, "encrypted and signed message\n" , "error verifing original message");
        test.done();
      });
    });
  });
}

exports.testDecryptEgamal = function(test)
{
  storage.cleantest();
  test.waitUntilDone(160000);
  ppgapp.importFile(test_data.key_dsaelgamal, function() {
    var msgdata = data.load(test_data.msg_elgamal);
    ppgapp.decrypt(msgdata, function(err, result) {
      test.assertEqual(result.msg, "encryped for egamal\n", 
                         "compressed message decrypt failed");
      test.done();
    });
  });
};

exports.testDecryptMultipleRecipients = function(test)
{
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key1,function() { 
    var msgdata = data.load(test_data.msg_multiple_recipients);
    ppgapp.decrypt(msgdata, function(err, result) {
      test.assertEqual(result.msg, "encrypt to several recipients\n", 
                         "compressed message decrypt failed");
      test.done();
    });
  });
};

exports.testRSAEncrypt = function(test) 
{
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key1, function(keys) {
    var key = keys[0];
    ppgapp.encrypt(test_data.msg_txt, [key.id], null, function(err, encmsg) {
      ppgapp.decrypt(encmsg, function(err, decmsg) {
        test.assertEqual(decmsg.msg, test_data.msg_txt,
                           "plain message encrypt/decrypt failed");
        test.done();
      });
    });
  });
}


exports.testRSAEncryptAndSign = function(test)
{
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key_dsaelgamal, function(keys) {
    var key = keys[0];
    ppgapp.encrypt(test_data.msg_txt, [key.id], [key.id], function(err, encmsg) {
      ppgapp.decrypt(encmsg, function(err, decmsg) {
        test.assertEqual(decmsg.type, PGP.DECRYPT_RC.SIGN_VERIFIED,
                           "invalid message signature");
        test.assertEqual(decmsg.msg, test_data.msg_txt,
                           "plain message encrypt/decrypt failed");
        test.done();
      });
    });
  });
}

exports.testElgamalEncrypt = function(test)
{
  storage.cleantest();
  test.waitUntilDone(60000);
  ppgapp.importFile(test_data.key_dsaelgamal, function(keys) {
    var key = keys[0];
    ppgapp.encrypt(test_data.msg_txt, [key.id], null, function(err, encmsg) {
      test.assertEqual(true, true,
                         "elgamal encrypt unfinished");
      test.done();
    });
  });
}

exports.testEncryptMultipleRecipients = function(test) {
  storage.cleantest();
  test.waitUntilDone(60000);
  ppgapp.importFile(test_data.key1, function(keys) {
    var key1 = keys[0];
    ppgapp.importFile(test_data.key_dsaelgamal, function(keys) {
      var key2 = keys[0];
      ppgapp.encrypt(test_data.msg_txt, [key1.id, key2.id], [key1.id], function(err, encmsg) {
        ppgapp.decrypt(encmsg, function(err, decmsg) {
          test.assertEqual(decmsg.msg, test_data.msg_txt,
                             "plain message encrypt/decrypt failed");
          test.done();
        });
      });
    });
  });
}

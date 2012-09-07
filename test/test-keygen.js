const PGP = require("pgp/openpgpdefs");
const misc = require('util/misc');
const {data} = require('self');
const {ppgapp} = require("ppgapp");
const {storage} = require('ring/storage');
const timers = require("timers");
const logger = require('util/logger').create();

var {prompt} = require("util/prompt");
prompt.newPassphrase = function() { return { passphrase: "1234" } };

var test_data = {key1:"test/key1.asc", 
                 msg_txt:"Hello World!!",
                 key_elgamal:"test/key_dsaegamal_unprotected.asc"};

exports.testGenerateRSAKeyEncryptAndDecrypt = function(test)
{
  storage.cleantest();
  var options = { 
    expireseconds : 3600*24*365*2, //1y
    name       : "test name",
    comment    : "test comment",
    email      : "test@ppgapp.org",
    passphrase : "1234",
    keypairBits : 1024,
    keyType     : PGP.PUBKEY.ALGO.RSA,
    subkeyType  : PGP.PUBKEY.ALGO.RSA,
  }

  test.waitUntilDone(80000);
  //we don't know when the domcrypt worker is ready
  timers.setTimeout(function() {
    ppgapp.generateKeypair(options, function(err, _key) {
      if (err) { logger.error(err); return }
      ppgapp.encrypt(test_data.msg_txt, [_key.id], null, function(err, encmsg) {
        if (err) { logger.error(err); return }
        ppgapp.decrypt(encmsg, function(err, decmsg) {
          if (err) { logger.error(err); return }
          test.assertEqual(decmsg.msg, test_data.msg_txt,
                             "plain message encrypt/decrypt failed");
          test.done();
        });
      });
    });
  }, 2000);
}

exports.testGenerateDSAElGamalKeyEncryptAndDecrypt = function(test)
{
  storage.cleantest();
  var options = { 
    expireseconds : 3600*365,
    name       : "test name",
    comment    : "",
    email      : "",
    passphrase : "",
    keypairBits : 1024,
    keyType    : PGP.PUBKEY.ALGO.DSA,
    subkeyType : PGP.PUBKEY.ALGO.ELGAMAL_E,
  }

  test.waitUntilDone(20000);
  //we don't know when the domcrypt worker is ready
  timers.setTimeout(function() {
    ppgapp.generateKeypair(options, function(err, _key) {
      if (err) { logger.error(err); return }
      test.assertEqual(_key.uids[0].name, "test name", "user id name mismatch");
      ppgapp.encrypt(test_data.msg_txt, [_key.id], null, function(err, encmsg) {
        if (err) { logger.error(err); return }
        ppgapp.decrypt(encmsg, function(err, decmsg) {
          if (err) { logger.error(err); return }
          test.assertEqual(decmsg.msg, test_data.msg_txt,
                             "plain message encrypt/decrypt failed");
          test.done();
        });
      });
    });
  }, 2000);
}

const PGP = require("pgp/openpgpdefs");
const {data} = require('self');
const {ppgapp} = require('ppgapp');
const {parsekeysfile} = require("pgp/key-parse");

var test_data  = {
                    key: "test/key3.asc", 
                    msg: "test/cleartextsign.asc", 
                    key_dsa: "test/key_dsaegamal_unprotected.asc", 
                    key_dsa3072: "test/key_dsaelgamal3072.asc", 
                    msg_dsasig3072: "test/msg_dsasig3072.asc",
                    key_dsa2048: "test/key_dsaelgamal2048.asc", 
                    msg_dsasig2048: "test/msg_dsasig2048.asc",
                    msg_dsasign: "test/msg_dsasign.asc"
                 };

exports.testVerifyClearSignMessage = function(test) {
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var msgdata = data.load(test_data.msg);
    ppgapp.verify(msgdata, function(err, _rc) {
      test.assertEqual(_rc, true, "Invalid signature");
      test.done();
    });
  });
};

exports.testVerifyDSAClearSignMessage = function(test) {
  test.waitUntilDone();
  ppgapp.importFile(test_data.key_dsa, function() { 
    var msgdata = data.load(test_data.msg_dsasign);
    ppgapp.verify(msgdata, function(err, _rc) {
      test.assertEqual(_rc, true, "Invalid signature");
      test.done();
    });
  });
};

exports.testVerifyDSA3072ClearSignMessage = function(test) {
  test.waitUntilDone(40000);
  ppgapp.importFile(test_data.key_dsa3072, function() { 
    var msgdata = data.load(test_data.msg_dsasig3072);

    ppgapp.verify(msgdata, function(err, _rc) {
      test.assertEqual(_rc, true, "Invalid signature");
      test.done();
    });
  });
};

exports.testVerifyDSA2048ClearSignMessage = function(test) {
  test.waitUntilDone();
  ppgapp.importFile(test_data.key_dsa2048, function() {
    var msgdata = data.load(test_data.msg_dsasig2048);
    ppgapp.verify(msgdata, function(err, _rc) {
      test.assertEqual(_rc, true, "Invalid signature");
      test.done();
    });
  });
};

const {ppgapp} = require('ppgapp');
const {storage} = require('ring/storage');

var test_data = { 
                  key1:"test/key1.asc", msg_txt:"Hello World!!", 
                  key_dsa: "test/key_dsaegamal_unprotected.asc", 
                  key_dsa3072: "test/key_dsaelgamal3072.asc", 
                  key_dsa2048: "test/key_dsaelgamal2048.asc", 
                };

exports.testSign = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key1, function(keys) {
    var key = keys[0];
    ppgapp.sign(test_data.msg_txt, key.id, function(err, response) {
      ppgapp.verify(response, function(err, _rc) {
        test.assertEqual(_rc, true, "Invalid signature");
        test.done();
      });
    });
  });
}

exports.testSignDSA1024 = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key1, function(keys) {
    var key = keys[0];
    ppgapp.sign(test_data.msg_txt, key.id, function(err, response) {
      ppgapp.verify(response, function(err, _rc) {
        test.assertEqual(_rc, true, "Invalid signature");
        test.done();
      });
    });
  });
}

exports.testSignDSA2048 = function(test)
{
  storage.cleantest();
  test.waitUntilDone(120000);
  ppgapp.importFile(test_data.key_dsa2048, function(keys) {
    var key = keys[0];
    ppgapp.sign(test_data.msg_txt, key.id, function(err, response) {
      ppgapp.verify(response, function(err, _rc) {
        test.assertEqual(_rc, true, "Invalid signature");
        test.done();
      });
    });
  });
}

exports.testSignDSA3072 = function(test) {
  storage.cleantest();
  test.waitUntilDone(60000);
  ppgapp.importFile(test_data.key_dsa3072, function(keys) {
    var key = keys[0];
    ppgapp.sign(test_data.msg_txt, key.id, function(err, response) {
      ppgapp.verify(response, function(err, _rc) {
        test.assertEqual(_rc, true, "Invalid signature");
        test.done();
      });
    });
  });
}

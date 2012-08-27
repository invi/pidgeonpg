const PGP = require("pgp/openpgpdefs");
const {data} = require('self');
const {ppgapp} = require('ppgapp');
const {parsekeysfile} = require("pgp/key-parse");
const misc = require('util/misc.js');
const armor = require('encode/armor');

var test_keys = { key_secret : "test/key1.asc",
                  key_secret_protected : "test/key2.asc",
                  key_testing: "test/key4.asc" };

function _compare_keyblocks(key1, key2) {
  var headers = [PGP.ARMOR.PUBLICKEY, PGP.ARMOR.PRIVATEKEY];
  return (armor.decode(key1, headers) == armor.decode(key2, headers));
}

exports.testDecryptKeyNotFound = function(test) {
  var armored_key1 = data.load(test_keys.key_testing);
	var key_uid_revoked = parsekeysfile(test_keys.key_testing)[0];
  var armored_key2 = key_uid_revoked.export_pubkey();
  test.assertEqual(_compare_keyblocks(armored_key1, armored_key2), true, "export pubkey failed");
}

exports.testSecretKey1 = function(test) {
  var armored_key1 = data.load(test_keys.key_secret);
	var key_secret = parsekeysfile(test_keys.key_secret)[0];
  var armored_key2 = key_secret.export_seckey();
  test.assertEqual(_compare_keyblocks(armored_key1, armored_key2), true, "export seckey failed");
}

exports.testSecretProtected1 = function(test) {
  var armored_key1 = data.load(test_keys.key_secret_protected);
	var key_secret = parsekeysfile(test_keys.key_secret_protected)[0];
  var armored_key2 = key_secret.export_seckey();
  test.assertEqual(_compare_keyblocks(armored_key1, armored_key2), true, "export seckey failed");
}

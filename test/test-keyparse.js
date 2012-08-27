const PGP = require("pgp/openpgpdefs");
const misc = require('util/misc');
const {IOBuf} = require('util/iobuf');
const {Parser} = require('pgp/parser');
const armor = require('encode/armor');
const data = require('self').data;
const file = require('file');
const url = require("url");
const {parsekeysfile} = require("pgp/key-parse");

var test_keys = { key_testing: "test/key4.asc",
        key_uidsigs: "test/key1_uidsigs.asc",
        key4: "test/key4.asc",
				key_protected: "test/key2.asc", 
				key_revoked: "test/key1_revoked.asc", 
				key_uid_revoked: "test/key1_uid_revoked.asc", 
				key_revokedsubkey: "test/key1_revokedsubkey.asc", 
				key_dsaelgamal: "test/key_dsaegamal.asc", 
				key_corrupted: "test/key_corrupted.asc"}

exports.testPacketParseCorrruptedKey = function(test) {
	//XXX Tests armor corruption not UID corruption
  test.assertRaises(
    function() {
	    var key_corrupted = parsekeysfile(test_keys.key_corrupted)[0];
    }
    , "PGP.ERR.BAD_CHECKSUM", "Key is not currupted!?");

}

exports.testPacketParseUIDRevokedKey = function(test) {
	test.waitUntilDone();
	var key_uid_revoked = parsekeysfile(test_keys.key_uid_revoked)[0];
	key_uid_revoked.verify(function(err) {
	  test.assertEqual(key_uid_revoked.getKeyIdStr(), "B5E4BE82180EE2D9", "KeyID missmatch");
    test.assertEqual(key_uid_revoked.uids[1].isRevoked(), true, "Key check uid revoked missmatch");
	  test.done();});
}

exports.testPacketParseProtectedKey = function(test) {
	test.waitUntilDone();
	var key_revoked = parsekeysfile(test_keys.key_protected)[0];
	key_revoked.verify(function(err) {
      test.assertEqual(key_revoked.getKeyIdStr(), "745E2369FB70C836", "KeyID missmatch");
	    test.done();
  });
}

exports.testPacketParseDSAEgamalKey = function(test) {
	test.waitUntilDone();
	var key_dsaelgamal = parsekeysfile(test_keys.key_dsaelgamal)[0];
	key_dsaelgamal.verify(function(err) {
      test.assertEqual(key_dsaelgamal.getKeyIdStr(), "F797395FF5FDD00A", "KeyID missmatch");
	    test.done();
  });
}

exports.testPacketParseRevokedSubKey = function(test) {
	test.waitUntilDone();
	var key_revoked = parsekeysfile(test_keys.key_revokedsubkey)[0];
	key_revoked.verify(function(err) {
	    test.assertEqual(key_revoked.getKeyIdStr(), "B5E4BE82180EE2D9", "KeyID missmatch");
    	test.assertEqual(key_revoked.subkeys[1].revsigs[0].isValid(), true, "SubKey check revoked missmatch");
	    test.done(); 
  });
}

exports.testPacketParse = function (test) {
	// keyid, fingerprint, valid, expired, revoked
	test.waitUntilDone();
	var key = parsekeysfile(test_keys.key_testing)[0];
    test.assertEqual(key.getKeyIdStr(), "C8EB526B5D35551A", "KeyID missmatch");
    test.assertEqual(key.isRevoked(), false, "Key check revoked missmatch");
    test.assertEqual(key.isExpired(), false, "Key check expired missmatch");
    test.done();
} 

exports.testUIDSigs = function(test) {
	test.waitUntilDone();
	var key = parsekeysfile(test_keys.key_uidsigs)[0];
  key.verify(function() {
    test.assertEqual(key.getKeyIdStr(), "B5E4BE82180EE2D9", "KeyID missmatch");
    test.assertEqual(key.isRevoked(), false, "Key check revoked missmatch");
    test.assertEqual(key.isExpired(), false, "Key check expired missmatch");
    test.done();
  });
}


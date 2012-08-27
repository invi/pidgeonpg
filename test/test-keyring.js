// ### Tests for status of keys when imported
const data    = require('self').data;
const {ppgapp}   = require('ppgapp');
const KEYSTATUS = require('pgp/openpgpdefs').KEYSTATUS;
const {storage} = require('ring/storage');
const cleantest = storage.cleantest;

var test_data  = {
      key: "test/key1.asc", 
      key_revoked: "test/key1_revoked.asc",
      key_uid_new: "test/key1_uid_new.asc",
      key_pubkey: "test/key4.asc",
      key_uid_revoked: "test/key1_uid_revoked.asc",
      key_uid_deleted: "test/key1_uid_deleted.asc",
      key_subkey_new: "test/key1_rsanewsubkey.asc",
      key_subkey_modified: "test/key1_subkey_modified_expiration_date.asc",
      key_subkey_revoked: "test/key1_revokedsubkey.asc",
};


exports.testKeyRingNewKey = function(test)
{
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var updated_key = keys[0];
    test.assertEqual(updated_key.ringstatus, KEYSTATUS.NEW , "New key not reported as new");
    test.done();
  });
}

exports.testKeyRingDeleteAndNewUid= function(test)
{
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var updated_key = keys[0];
    ppgapp.importFile(test_data.key_uid_deleted, function(keys) {
      var updated_key2 = keys[0];
      test.assertEqual(updated_key2.ringstatus, 
                       KEYSTATUS.CHANGED, 
                       "Key reported as unchanged (uid deleted and new added). It should be considered changed");
      test.done();
    });
  });
}

exports.testKeyRingUnchangedKey = function(test)
{
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var updated_key = keys[0];
    ppgapp.importFile(test_data.key, function(keys) {
      var updated_key2 = keys[0];
      test.assertEqual(updated_key2.ringstatus, KEYSTATUS.UNCHANGED, "Same key not reported as unchanged");
      test.done();
    });
  });
}

exports.testKeyRingChangedKey = function(test)
{
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var updated_key = keys[0];
    ppgapp.importFile(test_data.key_revoked, function(keys) {
      var updated_key2 = keys[0];
      test.assertEqual(updated_key2.ringstatus, KEYSTATUS.CHANGED, "Revoked key not reported as changed");
      test.done();
    });
  });
}

exports.testKeyRingNewSubKey= function(test)
{
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var updated_key = keys[0];
    ppgapp.importFile(test_data.key_subkey_new, function(keys) {
      var updated_key2 = keys[0];
      test.assertEqual(updated_key2.ringstatus, KEYSTATUS.CHANGED, "Key not reported as changed (new subkey added)");
      var new_subkey = false;
      var all_valid = true;
      for (var i=0;i<updated_key2.subkeys.length;i++)
        new_subkey |= updated_key2.subkeys[i].ringstatus == KEYSTATUS.NEW;

      for (var i=0;i<updated_key2.subkeys.length;i++) {
        all_valid &= updated_key2.subkeys[i].valid;
      }

      test.assert(new_subkey, "New subkey not detected");
      test.assert(all_valid, "All subkeys must be valid");
      test.done();
    });
  });
}

exports.testKeyRingModifiedSubKey= function(test)
{
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var updated_key = keys[0];
    ppgapp.importFile(test_data.key_subkey_modified, function(keys) {
      var updated_key2 = keys[0];
      test.assertEqual(updated_key2.ringstatus, KEYSTATUS.CHANGED, "Key not reported as changed (Subkey expiration date modified");
      var modified_subkey = false;
      for (var i=0;i<updated_key2.subkeys.length;i++)
        modified_subkey |= updated_key2.subkeys[i].ringstatus == KEYSTATUS.CHANGED;
      test.assert(modified_subkey, "Modified subkey not detected");
      test.done();
    });
  });
}


exports.testKeyRingNewUid= function(test)
{
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var updated_key = keys[0];
    ppgapp.importFile(test_data.key_uid_new, function(keys) {
      var updated_key2 = keys[0];
      test.assertEqual(updated_key2.ringstatus, KEYSTATUS.CHANGED, "Key not reported as changed (new uid added)");
      var new_uid = false;
      for (var i=0;i<updated_key2.uids.length;i++)
      {
        new_uid |= updated_key2.uids[i].ringstatus == KEYSTATUS.NEW;
      }
      test.assert(new_uid, "New uid not detected");
      test.done();
    });
  });
}


exports.testKeyRingRevokedUid = function(test)
{
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key_uid_new, function(keys) {
    var updated_key = keys[0];
    ppgapp.importFile(test_data.key_uid_revoked, function(keys) {
      var updated_key2 = keys[0];
      test.assertEqual(updated_key2.ringstatus, KEYSTATUS.CHANGED, "Key not reported as changed (uid revoked)");
      var revoked_uid = false;
      for (var i=0;i<updated_key2.uids.length;i++)
        revoked_uid |= updated_key2.uids[i].ringstatus == KEYSTATUS.CHANGED;
      test.assert(revoked_uid, "Revoked uid not detected");
      test.done();
    });
  });
}

exports.testKeyRingModifiedKey= function(test)
{   
  cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_data.key, function(keys) {
    var updated_key = keys[0];
    ppgapp.importFile(test_data.key_subkey_revoked, function(keys) {
      var updated_key2 = keys[0];
      test.assertEqual(updated_key2.ringstatus, KEYSTATUS.CHANGED, "Key not reported as changed (subkey revoked)");
      var changed_subkey= false;
      for (var i=0;i<updated_key2.subkeys.length;i++)
      {
        changed_subkey |= updated_key2.subkeys[i].ringstatus == KEYSTATUS.CHANGED; 
        changed_subkey |= updated_key2.subkeys[i].ringstatus == KEYSTATUS.NEW; 
      }
      test.assert(changed_subkey, "Changed (revoked) subkey not detected");
      test.done();
    });
  });
}



const {storage} = require('ring/storage');
const {ppgapp} = require('ppgapp');

var test_key = "test/key1.asc";
var test_key2 = "test/key2.asc";

exports.testSetDefaultKey = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    var key = imported_keys[0];
    storage.setDefaultKeyId(key.id);
    var defaultkeyid = storage.getDefault();
    test.assertEqual(defaultkeyid, key.id, 
                    "Error setting/getting default key");
    test.assertRaises(function() {
      storage.setDefaultKeyId("1234");
    },"Can't find key with ID: 1234", "Key should be missing and error thrown");
    test.done();
  });
}

exports.testSetOption = function(test) {
  storage.cleantest();
  storage.set_option("lang", "es");
  var readoption = storage.get_option("lang");
  test.assertEqual(readoption, "es", "Problem setting and getting lang option");
  test.assertRaises(function() { 
    storage.set_option("lalala", "lololo");
  }, "Option not available", "Missing error for option");
}

exports.testGetOption = function(test) {
  storage.cleantest();
  storage.get_option("lang");
  test.assertRaises(function() { 
    storage.get_option("lalala");
  }, "Option not available", "Missing error for option");
}

exports.testGetAllOptions = function(test) {
  storage.cleantest();
  storage.set_option("lang", "es");

  var alloptions = storage.get_all_options();
  test.assertEqual(alloptions.lang, "es", "Missmatch retreiving from all options");
}

exports.testCleanTest = function(test) {
  storage.cleantest();
  storage.set_option("lang", "es");
  storage.cleantest();
  var readoption = storage.get_option("lang");
  test.assertEqual(readoption, "en", "Cleantest fails");
}

exports.testRemoveAll = function(test) {
  storage.cleantest();
  storage.removeAllKeys();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    ppgapp.importFile(test_key2, function(imported_keys2) {
      test.assertEqual(storage.getAllKeys().length, 2, "Some key didnt import");
      storage.removeAllKeys();
      test.assertEqual(storage.getAllKeys().length, 0, "Keys weren't removed");
      test.done();
    });
  });
}

exports.testGetNumKeys = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    ppgapp.importFile(test_key2, function(imported_keys2) {
      var nkeys = storage.getNumKeys();
      test.assertEqual(nkeys, 2, "Some key isn't listed");
      test.done();
    });
  });
}

exports.testGetDefault = function(test) {
  storage.cleantest();
  test.waitUntilDone();
  ppgapp.importFile(test_key, function(imported_keys) {
    ppgapp.importFile(test_key2, function(imported_keys2) {
      storage.setDefaultKeyId(imported_keys2[0].id);
      var defaultkeyid = storage.getDefault();
      test.assertEqual(defaultkeyid, 
        imported_keys2[0].id, "Default key missmatch");
      test.done();
    });
  });
}


//exports.testAdd = function(test)
//{
//}
//exports.testUpdateKey = function(test)
//{
//}
//exports.testImportKey = function(test)
//{
//}
//exports.testRemove = function(test)
//{
//}
//exports.testFind = function(test)
//{
//}
//exports.testReplace = function(test)
//{
//}
//exports.testSearch = function(test)
//{
//}
//exports.testFetchKey = function(test)
//{
//}
//exports.testGetAllKeys = function(test)
//{
//}
//exports.testGetPublicKeys = function(test)
//{
//}
//exports.testGetPrivateKeys = function(test)
//{
//}

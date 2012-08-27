const {storage} = require('ring/storage');
const lang = require("util/lang");

exports.testLang = function(test) {
  storage.cleantest();
  test.assertEqual(lang.getLang(), null || "en", "Default lang err");
  test.assertEqual(lang.getStr("encrypt"), "Encrypt", "Default lang err");
  lang.setLang("en")
  test.assertEqual(lang.getLang(), "en", "Default lang err");
  test.assertEqual(lang.getStr("encrypt"), "Encrypt", "Default lang err");
  test.assertEqual(lang.getStr("generated", "1234"), "New pair generated! Key ID 1234", "Default lang err");
  lang.setLang("es")
  test.assertEqual(lang.getLang(), "es", "Default lang err");
  test.assertEqual(lang.getStr("encrypt"), "Cifrar", "Default lang err");
}

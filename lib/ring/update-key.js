const PGP  = require('pgp/openpgpdefs');
const misc = require('util/misc.js');
const logger = require("util/logger").create("update-key.js");
logger.stdout = true;

function _compare_sigs(_newsig, _ringsig) {
  var newsig = _newsig._sig.pkt;
  var ringsig = _ringsig._sig.pkt;
  if (newsig.data[0].length && (newsig.data[0].length == ringsig.data[0].length)) {
    if (newsig.data[0] == ringsig.data[0]) {
      return true;
    }
  }
  return false;
}

function _update_rev_sigs(newkey, ringkey) {
  logger.debug("_update_rev_sigs");
  for (var i=0; i<newkey.revsigs.length; i++) {
    var found=false;
    for (var j=0;j<ringkey.revsigs.length; j++)
    {
      if (_compare_sigs(newkey.revsigs[i], ringkey.revsigs[j])) {
        ringkey.revsigs[j].status.ringstatus = PGP.KEYSTATUS.UNCHANGED;
        found=true;
        break;
      }
    }
    logger.debug("newkey revsig(%d) found: " + found, i);
    if (!found) {
      ringkey.status.ringstatus = PGP.KEYSTATUS.CHANGED;
      var newrevsig = ringkey.addPacket(newkey.revsigs[i].getPacket());
      newrevsig.status.ringstatus = PGP.KEYSTATUS.NEW;
    }
  }
}

function _update_uid_sigs(newuid, ringuid) {
  var sigtypes = ['revsigs', 'selfsigs', 'sigs'];
  var _status = PGP.KEYSTATUS.UNCHANGED;
  for (var t in sigtypes) {
    var newsigs = newuid[sigtypes[t]];
    var ringsigs = ringuid[sigtypes[t]];
    for (var i=0;i<newsigs.length; i++) {
      newsigs[i].status = PGP.KEYSTATUS.UNCHANGED;
      var found = false;
      for (var j=0;j<ringsigs.length; j++) {
        if (_compare_sigs(newsigs[i], ringsigs[j])) {
          found = true;
          break;
        }
      }
      if (!found) {
        _status = PGP.KEYSTATUS.CHANGED;
        var newsig = ringuid.addPacket(newsigs[i].getPacket());
        newsig.status.ringstatus = PGP.KEYSTATUS.NEW;
      }
    }
  }
  return _status;
}

function _update_uids(newkey, ringkey) {
  var uidstatus = PGP.KEYSTATUS.UNCHANGED;
  for (var i=0; i<newkey.uids.length; i++) {
    var found = false;
    for (var j=0; j<ringkey.uids.length; j++) {
      if (newkey.uids[i].getName() == ringkey.uids[j].getName()) {
        found = true;
        var uidstatus = _update_uid_sigs(newkey.uids[i], ringkey.uids[j]);
        ringkey.uids[j].status.ringstatus = uidstatus;
        if (uidstatus == PGP.KEYSTATUS.CHANGED)
          ringkey.status.ringstatus = PGP.KEYSTATUS.CHANGED;
      }
    }
    if (!found) {
      ringkey.status.ringstatus = PGP.KEYSTATUS.CHANGED;

      var newuid = ringkey.addPacket(newkey.uids[i].getPacket())
      newuid.status.ringstatus = PGP.KEYSTATUS.NEW;

      for (var j=0;j<newkey.uids[i].selfsigs.length;j++)
        ringkey.addPacket(newkey.uids[i].selfsigs[j].getPacket());
      for (var j=0;j<newkey.uids[i].sigs.length;j++)
        ringkey.addPacket(newkey.uids[i].sigs[j].getPacket()); 
      for (var j=0;j<newkey.uids[i].revsigs.length;j++)
        ringkey.addPacket(newkey.uids[i].revsigs[j].getPacket()); 

      newuid.updateStatus();
    }
  }
}

function _update_subkey_sigs(newsubkey, ringsubkey) {
  var sigtypes = ['revsigs', 'selfsigs'];

  var _status = PGP.KEYSTATUS.UNCHANGED;
  for (var t in sigtypes) {
    var newsigs = newsubkey[sigtypes[t]];
    var ringsigs = ringsubkey[sigtypes[t]];
    for (var i=0;i<newsigs.length; i++) {
      var found = false;
      for (var j=0;j<ringsigs.length; j++) {
        if (newsigs[i].status.valid) {
          if (_compare_sigs(newsigs[0], ringsigs[j])) {
            found = true;
            break;
          }
        }
      }
      if (!found) {
        _status = PGP.KEYSTATUS.CHANGED;
        var newsig = ringsubkey.addPacket(newsigs[i].getPacket());
        newsig.status = PGP.KEYSTATUS.NEW;
      }
    }
  }
  return _status;
}

function _update_subkeys(newkey, ringkey) {
  for (var i=0; i<newkey.subkeys.length; i++) {
    var found = false;
    for (var j=0; j<ringkey.subkeys.length; j++) {
      if (newkey.subkeys[i].getKeyId() == ringkey.subkeys[j].getKeyId()) {
        found = true;
        var skstatus = _update_subkey_sigs(newkey.subkeys[i], ringkey.subkeys[j]);
        ringkey.subkeys[j].status.ringstatus = skstatus;
        if (skstatus == PGP.KEYSTATUS.CHANGED)
        {
          ringkey.status.ringstatus = PGP.KEYSTATUS.CHANGED;
        }
        break;
      } 
    }
    if (!found) {
      ringkey.status.ringstatus = PGP.KEYSTATUS.CHANGED;
      var newsubkey = ringkey.addPacket(newkey.subkeys[i].getPacket());
      newsubkey.status.ringstatus = PGP.KEYSTATUS.NEW;
      for (var j=0;j<newkey.subkeys[i].selfsigs.length;j++) {
        var sig = ringkey.addPacket(newkey.subkeys[i].selfsigs[j].getPacket());
        sig.status.valid = true;
      }
      for (var j=0;j<newkey.subkeys[i].revsigs.length;j++) {
        var sig = ringkey.addPacket(newkey.subkeys[i].revsigs[j].getPacket()); 
        sig.status.valid = true;
      }
      newsubkey.updateStatus();
    }
  }
}

exports.update_key = function(newkey, ringkey) {
  logger.debug("update Key ID %d", newkey.getKeyIdStr());
  ringkey.status.ringstatus = PGP.KEYSTATUS.UNCHANGED;
  _update_rev_sigs(newkey, ringkey);
  _update_uids(newkey, ringkey);
  _update_subkeys(newkey, ringkey);
  ringkey.updateStatus();
  return ringkey;
}

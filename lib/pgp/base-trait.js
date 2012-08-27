const misc = require("util/misc");
let Trait = require('light-traits').Trait;

let t = Trait({
//  _check_status: Trait.required,
  getPacket: Trait.required,
  getPacketType: Trait.required,
  getDigest: Trait.required,
  getFormattedPacket: Trait.required,
  isVerified: function() { return this.status.verified },
  isValid: function() { return this.status.valid },
  isRevoked: function() { return this.status.revoked },
  verify: Trait.required,
})

exports.BaseTrait = t;

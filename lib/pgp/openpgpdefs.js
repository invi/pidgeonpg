exports.DECRYPT_RC = {
  ERR: -1,
  NOT_SIGNED: 0,
  SIGN_VERIFIED: 1,
  SIGN_UNKNOW_KEY: 2,
  SIGN_NOT_VALID: 3
};

exports.ERR = { 
  INV_SECKEY: -4,
  NO_SIGCLASS : -5,
  NO_ERROR : 0,
  GENERAL : 1,
  UNKNOWN_PACKET : 2,
  UNKNOWN_VERSION : 3,
  PUBKEY_ALGO : 4,
  DIGEST_ALGO : 5,
  BAD_PUBKEY : 6,
  BAD_SECKEY : 7,
  BAD_SIGNATURE : 8,
  NO_PUBKEY : 9,
  CHECKSUM : 10,
  BAD_PASSPHRASE : 11,
  CIPHER_ALGO : 12,
  KEYRING_OPEN : 13,
  INV_PACKET : 14,
  INV_ARMOR : 15,
  NO_USER_ID : 16,
  NO_SECKEY : 17,
  WRONG_SECKEY : 18,
  BAD_KEY : 19,
  COMPR_ALGO : 20,
  NO_PRIME : 21,
  NO_ENCODING_METHOD : 22,
  NO_ENCRYPTION_SCHEME : 23,
  NO_SIGNATURE_SCHEME : 24,
  INV_ATTR : 25,
  NO_VALUE : 26,
  NOT_FOUND : 27,
  VALUE_NOT_FOUND : 28,
  SYNTAX : 29,
  BAD_MPI : 30,
  INV_PASSPHRASE : 31,
  SIG_CLASS : 32,
  RESOURCE_LIMIT : 33,
  INV_KEYRING : 34,
  TRUSTDB : 35,
  BAD_CERT : 36,
  INV_USER_ID : 37,
  UNEXPECTED : 38,
  TIME_CONFLICT : 39,
  KEYSERVER : 40,
  WRONG_PUBKEY_ALGO : 41,
  TRIBUTE_TO_D_A : 42,
  WEAK_KEY : 43,
  INV_KEYLEN : 44,
  INV_ARG : 45,
  BAD_URI : 46,
  INV_URI : 47,
  NETWORK : 48,
  UNKNOWN_HOST : 49,
  SELFTEST_FAILED : 50,
  NOT_ENCRYPTED : 51,
  NOT_PROCESSED : 52,
  UNUSABLE_PUBKEY : 53,
  UNUSABLE_SECKEY : 54,
  INV_VALUE : 55,
  BAD_CERT_CHAIN : 56,
  MISSING_CERT : 57,
  NO_DATA : 58,
  BUG : 59,
  NOT_SUPPORTED : 60,
  INV_OP : 61,
  TIMEOUT : 62,
  INTERNAL : 63,
  EOF_GCRYPT : 64,
  INV_OBJ : 65,
  TOO_SHORT : 66,
  TOO_LARGE : 67,
  NO_OBJ : 68,
  NOT_IMPLEMENTED : 69,
  CONFLICT : 70,
  INV_CIPHER_MODE : 71,
  INV_FLAG : 72,
  INV_HANDLE : 73,
  TRUNCATED : 74,
  INCOMPLETE_LINE : 75,
  INV_RESPONSE : 76,
  NO_AGENT : 77,
  AGENT : 78,
  INV_DATA : 79,
  ASSUAN_SERVER_FAULT : 80,
  ASSUAN : 81,
  INV_SESSION_KEY : 82,
  INV_SEXP : 83,
  UNSUPPORTED_ALGORITHM : 84,
  NO_PIN_ENTRY : 85,
  PIN_ENTRY : 86,
  BAD_PIN : 87,
  INV_NAME : 88,
  BAD_DATA : 89,
  INV_PARAMETER : 90,
  WRONG_CARD : 91,
  NO_DIRMNGR : 92,
  DIRMNGR : 93,
  CERT_REVOKED : 94,
  NO_CRL_KNOWN : 95,
  CRL_TOO_OLD : 96,
  LINE_TOO_LONG : 97,
  NOT_TRUSTED : 98,
  CANCELED : 99,
  BAD_CA_CERT : 100,
  CERT_EXPIRED : 101,
  CERT_TOO_YOUNG : 102,
  UNSUPPORTED_CERT : 103,
  UNKNOWN_SEXP : 104,
  UNSUPPORTED_PROTECTION : 105,
  CORRUPTED_PROTECTION : 106,
  AMBIGUOUS_NAME : 107,
  CARD : 108,
  CARD_RESET : 109,
  CARD_REMOVED : 110,
  INV_CARD : 111,
  CARD_NOT_PRESENT : 112,
  NO_PKCS15_APP : 113,
  NOT_CONFIRMED : 114,
  CONFIGURATION : 115,
  NO_POLICY_MATCH : 116,
  INV_INDEX : 117,
  INV_ID : 118,
  NO_SCDAEMON : 119,
  SCDAEMON : 120,
  UNSUPPORTED_PROTOCOL : 121,
  BAD_PIN_METHOD : 122,
  CARD_NOT_INITIALIZED : 123,
  UNSUPPORTED_OPERATION : 124,
  WRONG_KEY_USAGE : 125,
  NOTHING_FOUND : 126,
  WRONG_BLOB_TYPE : 127,
  MISSING_VALUE : 128,
  HARDWARE : 129,
  PIN_BLOCKED : 130,
  USE_CONDITIONS : 131,
  PIN_NOT_SYNCED : 132,
  INV_CRL : 133,
  BAD_BER : 134,
  INV_BER : 135,
  ELEMENT_NOT_FOUND : 136,
  IDENTIFIER_NOT_FOUND : 137,
  INV_TAG : 138,
  INV_LENGTH : 139,
  INV_KEYINFO : 140,
  UNEXPECTED_TAG : 141,
  NOT_DER_ENCODED : 142,
  NO_CMS_OBJ : 143,
  INV_CMS_OBJ : 144,
  UNKNOWN_CMS_OBJ : 145,
  UNSUPPORTED_CMS_OBJ : 146,
  UNSUPPORTED_ENCODING : 147,
  UNSUPPORTED_CMS_VERSION : 148,
  UNKNOWN_ALGORITHM : 149,
  INV_ENGINE : 150,
  PUBKEY_NOT_TRUSTED : 151,
  DECRYPT_FAILED : 152,
  KEY_EXPIRED : 153,
  SIG_EXPIRED : 154,
  ENCODING_PROBLEM : 155,
  INV_STATE : 156,
  DUP_VALUE : 157,
  MISSING_ACTION : 158,
  MODULE_NOT_FOUND : 159,
  INV_OID_STRING : 160,
  INV_TIME : 161,
  INV_CRL_OBJ : 162,
  UNSUPPORTED_CRL_VERSION : 163,
  INV_CERT_OBJ : 164,
  UNKNOWN_NAME : 165,
  LOCALE_PROBLEM : 166,
  NOT_LOCKED : 167,
  PROTOCOL_VIOLATION : 168,
  INV_MAC : 169,
  INV_REQUEST : 170,
  UNKNOWN_EXTN : 171,
  UNKNOWN_CRIT_EXTN : 172,
  LOCKED : 173,
  UNKNOWN_OPTION : 174,
  UNKNOWN_COMMAND : 175,
  NOT_OPERATIONAL : 176,
  NO_PASSPHRASE : 177,
  NO_PIN : 178,
  NOT_ENABLED : 179,
  NO_ENGINE : 180,
  MISSING_KEY : 181,
  TOO_MANY : 182,
  LIMIT_REACHED : 183,
  NOT_INITIALIZED : 184,
  MISSING_ISSUER_CERT : 185,
  FULLY_CANCELED : 198,
  UNFINISHED : 199,
  BUFFER_TOO_SHORT : 200,
  SEXP_INV_LEN_SPEC : 201,
  SEXP_STRING_TOO_LONG : 202,
  SEXP_UNMATCHED_PAREN : 203,
  SEXP_NOT_CANONICAL : 204,
  SEXP_BAD_CHARACTER : 205,
  SEXP_BAD_QUOTATION : 206,
  SEXP_ZERO_PREFIX : 207,
  SEXP_NESTED_DH : 208,
  SEXP_UNMATCHED_DH : 209,
  SEXP_UNEXPECTED_PUNC : 210,
  SEXP_BAD_HEX_CHAR : 211,
  SEXP_ODD_HEX_NUMBERS : 212,
  SEXP_BAD_OCT_CHAR : 213,
  ASS_GENERAL : 257,
  ASS_ACCEPT_FAILED : 258,
  ASS_CONNECT_FAILED : 259,
  ASS_INV_RESPONSE : 260,
  ASS_INV_VALUE : 261,
  ASS_INCOMPLETE_LINE : 262,
  ASS_LINE_TOO_LONG : 263,
  ASS_NESTED_COMMANDS : 264,
  ASS_NO_DATA_CB : 265,
  ASS_NO_INQUIRE_CB : 266,
  ASS_NOT_A_SERVER : 267,
  ASS_NOT_A_CLIENT : 268,
  ASS_SERVER_START : 269,
  ASS_READ_ERROR : 270,
  ASS_WRITE_ERROR : 271,
  ASS_TOO_MUCH_DATA : 273,
  ASS_UNEXPECTED_CMD : 274,
  ASS_UNKNOWN_CMD : 275,
  ASS_SYNTAX : 276,
  ASS_CANCELED : 277,
  ASS_NO_INPUT : 278,
  ASS_NO_OUTPUT : 279,
  ASS_PARAMETER : 280,
  ASS_UNKNOWN_INQUIRE : 281,

  PUBKEY_ALGO_NI : 1004,
  DIGEST_ALGO_NI : 1005,
  USER_1 : 1024,
  USER_2 : 1025,
  USER_3 : 1026,
  USER_4 : 1027,
  USER_5 : 1028,
  USER_6 : 1029,
  USER_7 : 1030,
  USER_8 : 1031,
  USER_9 : 1032,
  USER_10 : 1033,
  USER_11 : 1034,
  USER_12 : 1035,
  USER_13 : 1036,
  USER_14 : 1037,
  USER_15 : 1038,
  USER_16 : 1039,
  MISSING_ERRNO : 16381,
  UNKNOWN_ERRNO : 16382,
  EOF : 16383,
}

exports.PKT = { 
  NONE          : 0,
  PUBKEY_ENC    : 1,  /* Public key encrypted packet. */
  SIGNATURE     : 2,  /* Secret key encrypted packet. */
  SYMKEY_ENC    : 3,  /* Session key packet. */
  ONEPASS_SIG   : 4,  /* One pass sig packet. */
  SECRET_KEY    : 5,  /* Secret key. */
  PUBLIC_KEY    : 6,  /* Public key. */
  SECRET_SUBKEY : 7,  /* Secret subkey. */
  COMPRESSED    : 8,  /* Compressed data packet. */
  ENCRYPTED     : 9,  /* Conventional encrypted data. */
  MARKER        : 10, /* Marker packet. */
  PLAINTEXT     : 11, /* Literal data packet. */
  RING_TRUST    : 12, /* Keyring trust packet. */
  USER_ID       : 13, /* User id packet. */
  PUBLIC_SUBKEY : 14, /* Public subkey. */
  OLD_COMMENT   : 16, /* Comment packet from an OpenPGP draft. */
  ATTRIBUTE     : 17, /* PGP's attribute packet. */
  ENCRYPTED_MDC : 18, /* Integrity protected encrypted data. */
  MDC           : 19, /* Manipulation detection code packet. */
  COMMENT       : 61, /* new comment packet (GnuPG specific). */
  GPG_CONTROL   : 63  /* internal control packet (GnuPG specific). */
}

exports.SIGSUBPKT = {
  TEST_CRITICAL : -3,
  LIST_UNHASHED : -2,
  LIST_HASHED   : -1,
  NONE          :  0,
  SIG_CREATED   :  2, /* Signature creation time. */
  SIG_EXPIRE    :  3, /* Signature expiration time. */
  EXPORTABLE    :  4, /* Exportable. */
  TRUST         :  5, /* Trust signature. */
  REGEXP        :  6, /* Regular expression. */
  REVOCABLE     :  7, /* Revocable. */
  KEY_EXPIRE    :  9, /* Key expiration time. */
  ARR           : 10, /* Additional recipient request. */
  PREF_SYM      : 11, /* Preferred symmetric algorithms. */
  REV_KEY       : 12, /* Revocation key. */
  ISSUER        : 16, /* Issuer key ID. */
  NOTATION      : 20, /* Notation data. */
  PREF_HASH     : 21, /* Preferred hash algorithms. */
  PREF_COMPR    : 22, /* Preferred compression algorithms. */
  KS_FLAGS      : 23, /* Key server preferences. */
  PREF_KS       : 24, /* Preferred key server. */
  PRIMARY_UID   : 25, /* Primary user id. */
  POLICY        : 26, /* Policy URL. */
  KEY_FLAGS     : 27, /* Key flags. */
  SIGNERS_UID   : 28, /* Signer's user id. */
  REVOC_REASON  : 29, /* Reason for revocation. */
  FEATURES      : 30, /* Feature flags. */

  SIGNATURE     : 32, /* Embedded signature. */

  FLAG_CRITICAL : 128
}

exports.KEY_FLAGS = {
  "CS" : 0x01, //This key may be used to certify other keys.

  "SD" : 0x02, // This key may be used to sign data.

  "EC" : 0x04, // This key may be used to encrypt communications.

  "ES" : 0x08, // This key may be used to encrypt storage.

  "SM" : 0x10, // The private component of this key may have been split
             // by a secret-sharing mechanism.

  "AU" : 0x20, // This key may be used for authentication.

  "MP" : 0x80, // The private component of this key may be in the
               // possession of more than one person.

}

exports.CIPHER = {
  ALGO: {
    NONE:     0,
    IDEA:     1,
    DES3:     2,
    CAST5:    3,
    BLOWFISH: 4,
    AES:      7,
    AES192:   8, 
    AES256:   9 
  },
  ALGO_INV: {
    0: "NONE",
    1: "IDEA",
    2: "DES3",
    3: "CAST5",
    4: "BLOWFISH",
    7: "AES",
    8: "AES192",
    9: "AES256",
  }
}
    
exports.PUBKEY = {
  ALGO: {
    RSA: 1, 
    RSA_E: 2,
    RSA_S: 3,
    ELGAMAL_E: 16,
    DSA: 17, 
    ECDH: 18,
    ECDSA: 19,
    ELGAMAL: 20
  },
  /* Flags describing usage capabilities of a PK algorithm. */
  USAGE: {
    SIGN: 1,  /* Good for signatures. */
    ENCR: 2,  /* Good for encryption. */
    CERT: 4,  /* Good to certify other keys. */
    AUTH: 8,  /* Good for authentication. */
    UNKN: 128 /* Unknown usage flag. */

  },
  //XXX not used
  NSIG: {
    1: {
          PKEY: "ne",
          SKEY: "nedpqu",
          ENC:  "a",
          SIG:  "s",
          GRIP: "n"
       }
  }
}

exports.HASH = {
  MD5:        1,
  SHA1:       2,
  RIPEMD160:  3,
  SHA256:     8,
  SHA384:     9,
  SHA512:    10,
  SHA224:    11
}

exports.HASH_INV = {
  1:  "MD5",
  2:  "SHA1",
  3:  "RIPEMD160",
  8:  "SHA256",
  9:  "SHA384",
  10: "SHA512",
  11: "SHA224"
}

exports.SIGCLASS = {
  BINARY     : 0x00,
  CANONICAL  : 0x01,
  CASUAL_SIG : 0x12,
  KEY_SIG    : 0x13,
  UID_SIG    : 0x10,
  DIRECT_SIG : 0x1F,
  SUBKEY_SIG : 0x18,
  KEY_REV    : 0x20,
  UID_REV    : 0x30,
  SUBKEY_REV : 0x28,
}

exports.SIGCLASS_STR = {
  0x00 : 'Signature of a binary document',
  0x01 : 'Signature of a canonical text document',
  0x02 : 'Standalone signature',
  0x10 : 'Generic certification of a User ID and Public-Key packet',
  0x11 : 'Persona certification of a User ID and Public-Key packet',
  0x12 : 'Casual certification of a User ID and Public-Key packet',
  0x13 : 'Positive certification of a User ID and Public-Key packet',
  0x18 : 'Subkey Binding Signature',
  0x19 : 'Primary Key Binding Signature',
  0x1F : 'Signature directly on a key',
  0x20 : 'Key revocation signature',
  0x28 : 'Subkey revocation signature',
  0x30 : 'Certification revocation signature',
  0x40 : 'Timestamp signature',
  0x50 : 'Third-Party Confirmation signature'
}

exports.ARMOR = {
  PUBLICKEY: {
    BEGIN: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    END: "-----END PGP PUBLIC KEY BLOCK-----",
  },
  PRIVATEKEY: {
    BEGIN: "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    END: "-----END PGP PRIVATE KEY BLOCK-----",
  },
  MESSAGE: {
    BEGIN: "-----BEGIN PGP MESSAGE-----",
    END: "-----END PGP MESSAGE-----",
  },
  SIGNATURE: {
    BEGIN: "-----BEGIN PGP SIGNATURE-----",
    END: "-----END PGP SIGNATURE-----",
  },
  SIGNEDMESSAGE: {
    BEGIN: "-----BEGIN PGP SIGNED MESSAGE-----",
  }
}

exports.COMPRESS_ALGO = {
  UNCOMPRESSED: 0,
  ZIP: 1,
  ZLIB: 2,
  BZIP2: 3
}

exports.VALIDITY = {
  OK: 0,
  UNCHECKED: 1,
  INVALID: 2,
  EXPIRED: 3,
  REVOKED: 4
}

exports.KEYSTATUS = {
  NEW: 0,
  CHANGED: 1,
  UNCHANGED: 2
}

exports.MAX_EXTERN_MPI_BITS = 4096;

exports.PUBKEY_ALGOS = { 
  1:  'RSA',
  2:  'RSA Encryption',
  16: "ElGamal Encryption",
  17: "DSA",
}

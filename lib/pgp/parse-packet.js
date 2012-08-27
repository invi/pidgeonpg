const PGP = require('pgp/openpgpdefs');
const misc = require('util/misc');
const {string_to_u32} = misc;
const photoid = require('pgp/photoid');
const base64Encode = require("api-utils/base64").encode;
const {sprintf} = require('util/sprintf');
const {getStr} = require('util/lang');
const logger = require("util/logger").create("parser.js");

var Parser = {
  dump_sig_subpkt: function(hashed, type, buffer, length) {
    var tmp = sprintf("%ssubpkt %d len %d (" ,
                       hashed ? "hashed " : "", type, length);
    
    if (length > buffer.length) {
      logger.error("too short: buffer is only %u)\n");
      return;
    }
    
    switch (type) {
      case PGP.SIGSUBPKT.SIG_CREATED:
        if (length >= 4)
          tmp += "sig created " + string_to_u32(buffer);
        break;
      case PGP.SIGSUBPKT.SIG_EXPIRE:
        if (length >= 4) {
          if (string_to_u32 (buffer))
            tmp += "sig expires after" + string_to_u32(buffer);
          else
            tmp += "sig does not expire";
        }
        break;
      case PGP.SIGSUBPKT.EXPORTABLE:
        if (length)
        	tmp += "%sexportable", buffer[0] ? "" : "not ";
        break;
      case PGP.SIGSUBPKT.TRUST:
        if (length != 2)
          tmp += "[invalid trust subpacket]";
        else
          tmp += "trust signature of depth "+buffer[0]+", value "+buffer[1];
        break;
      case PGP.SIGSUBPKT.REGEXP:
        if (!length)
          tmp += "[invalid regexp subpacket]";
        else
          tmp += "regular expression:" + buffer;
        break;
      case PGP.SIGSUBPKT.REVOCABLE:
        if (length)
          tmp += (buffer[0] ? "" : "not ") + "revocable";
        break;
      case PGP.SIGSUBPKT.KEY_EXPIRE:
        if (length >= 4) {
          if (string_to_u32 (buffer))
            tmp += "key expires after "+string_to_u32 (buffer);
          else
            tmp += "key does not expire";
        }
        break;
      case PGP.SIGSUBPKT.PREF_SYM:
        tmp += "pref-sym-algos:";
        for (i = 0; i < length; i++)
          tmp += " "+buffer[i];
        break;
      case PGP.SIGSUBPKT.REV_KEY:
        tmp += "revocation key: ";
        if (length < 22)
          tmp += "[too short]";
        else {
          tmp += sprintf("c=%02x a=%d f=", buffer[0], buffer[1]);
          for (i = 2; i < length; i++)
            tmp += "%02X", buffer[i];
        }
        break;
      case PGP.SIGSUBPKT.ISSUER:
        if (length >= 8)
          tmp += sprintf("issuer key ID %08X", buffer);
        break;
      case PGP.SIGSUBPKT.NOTATION:
        logger.debug("notation: ");
        if (length < 8)
          logger.debug("[too short]");
        else {
          s = buffer;
          n1 = (s[4] << 8) | s[5];
          n2 = (s[6] << 8) | s[7];
          s += buffer.slice(8);
          if (8 + n1 + n2 != length)
            logger.debug("[error]");
          else
          {
            //es_write_sanitized (listfp, s, n1, ")", NULL);
            //es_putc ('=', listfp);
            //
            //if (*buffer & 0x80)
            //  es_write_sanitized (listfp, s + n1, n2, ")", NULL);
            //else
            //  p = "[not human readable]";
          }
        }
        break;
      case PGP.SIGSUBPKT.PREF_HASH:
        tmp += "pref-hash-algos:";
        for (i = 0; i < length; i++)
          tmp += sprintf(" %d", buffer[i]);
        break;
      case PGP.SIGSUBPKT.PREF_COMPR:
        tmp += "pref-zip-algos:";
        for (i = 0; i < length; i++)
          tmp += sprintf(" %d", buffer[i]);
        break;
      case PGP.SIGSUBPKT.KS_FLAGS:
        tmp += "key server preferences:";
        for (i = 0; i < length; i++)
          tmp += sprintf(" %02X", buffer[i]);
        break;
      case PGP.SIGSUBPKT.PREF_KS:
        tmp += "preferred key server: ";
        //es_write_sanitized (listfp, buffer, length, ")", NULL);
        break;
      case PGP.SIGSUBPKT.PRIMARY_UID:
        tmp += "primary user ID";
        break;
      case PGP.SIGSUBPKT.POLICY:
        tmp  += "policy: ";
        //es_write_sanitized (listfp, buffer, length, ")", NULL);
        break;
      case PGP.SIGSUBPKT.KEY_FLAGS:
        tmp += "key flags:";
        for (var i = 0; i < length; i++)
          tmp += sprintf(" %02X", buffer[i]);
        break;
      case PGP.SIGSUBPKT.SIGNERS_UID:
        tmp += "signer's user ID";
        break;
      case PGP.SIGSUBPKT.REVOC_REASON:
        if (length) {
            tmp += sprintf("revocation reason 0x%02x (", buffer);
            //es_write_sanitized (listfp, buffer + 1, length - 1, ")", NULL);
            tmp += ")";
          }
        break;
      case PGP.SIGSUBPKT.ARR:
        tmp += "Big Brother's key (ignored): ";
        if (length < 22)
          tmp += "[too short]";
        else {
          tmp += sprintf("c=%02x a=%d f=", buffer[0], buffer[1]);
          //if (length > 2)
          //  es_write_hexstring (listfp, buffer+2, length-2, 0, NULL);
        }
        break;
      case PGP.SIGSUBPKT.FEATURES:
        tmp += "features:";
        for (var i=0; i<length;i++)
          tmp += sprintf(" %02X", buffer[i]);
        break;
      case PGP.SIGSUBPKT.SIGNATURE:
        tmp += "signature: ";
        if (length < 17)
          tmp += "[too short]";
        else
          tmp += sprintf("v%d, class 0x%02X, algo %d, digest algo %d",
                          buffer[0],
                          buffer[0] == 3 ? buffer[2] : buffer[1],
                          buffer[0] == 3 ? buffer[15] : buffer[2],
                          buffer[0] == 3 ? buffer[16] : buffer[3]);
        break;
      default:
        if (type >= 100 && type <= 110)
        	tmp += "experimental / private subpacket";
        else
          tmp += "?";
        break;
    }
  },
    
  parse_sig_subpkt2: function(sig, reqtype) {
    var p;
    p = this.parse_sig_subpkt (sig.hashed, reqtype);
    if (!p)
      p = this.parse_sig_subpkt (sig.unhashed, reqtype);
    return p;
  },
  
  /*
   * Returns: >= 0 use this offset into buffer
   *	    -1 explicitly reject returning this type
   *	    -2 subpacket too short
   */
  parse_one_sig_subpkt: function(buffer, n, type) {
    switch (type) {
      case PGP.SIGSUBPKT.REV_KEY:
        if (n < 22)
      	  break;
        return 0;
      case PGP.SIGSUBPKT.SIG_CREATED:
      case PGP.SIGSUBPKT.SIG_EXPIRE:
      case PGP.SIGSUBPKT.KEY_EXPIRE:
        if (n < 4)
  	      break;
        return 0;
      case PGP.SIGSUBPKT.KEY_FLAGS:
      case PGP.SIGSUBPKT.KS_FLAGS:
      case PGP.SIGSUBPKT.PREF_SYM:
      case PGP.SIGSUBPKT.PREF_HASH:
      case PGP.SIGSUBPKT.PREF_COMPR:
      case PGP.SIGSUBPKT.POLICY:
      case PGP.SIGSUBPKT.PREF_KS:
      case PGP.SIGSUBPKT.FEATURES:
      case PGP.SIGSUBPKT.REGEXP:
        return 0;
      case PGP.SIGSUBPKT.SIGNATURE:
      case PGP.SIGSUBPKT.EXPORTABLE:
      case PGP.SIGSUBPKT.REVOCABLE:
      case PGP.SIGSUBPKT.REVOC_REASON:
        if (!n)
          break;
        return 0;
      case PGP.SIGSUBPKT.ISSUER:	/* issuer key ID */
        if (n < 8)
  	      break;
        return 0;
      case PGP.SIGSUBPKT.NOTATION:
        /* minimum length needed, and the subpacket must be well-formed
           where the name length and value length all fit inside the
           packet. */
        if (n < 8 || 8 + ((buffer[4] << 8) | buffer[5]) + ((buffer[6] << 8) | buffer[7]) != n)
        	break;
        return 0;
      case PGP.SIGSUBPKT.PRIMARY_UID:
        if (n != 1)
  	      break;
        return 0;
      case PGP.SIGSUBPKT.TRUST:
        if (n != 2)
  	      break;
        return 0;
      default:
        return 0;
      }
    return -2;
  },
  
  parse_sig_subpkt: function(pktbuf, reqtype) {
    var buffer,
        buflen,
        type,
        offset,
        n = 0,
        i = 0,
        seq = 0;
  
    buffer = pktbuf.data;
    buflen = pktbuf.len;
    var too_short = function() {
      logger.info("buffer shorter than subpacket\n");
      return null;
    }
  
    while (i < buflen)
    {
      n = buffer[i++];
      if (n == 255) /* 4 byte length header.  */
    	{
  	    if (buflen < 4)
          return too_short();
  
  	    n = (buffer[i] << 24) | (buffer[i+1] << 16)
  	        | (buffer[i+2] << 8) | buffer[i+3];
  	    i += 4;
  	  }
      else if (n >= 192) /* 4 byte special encoded length header.  */
  	  {
  	    if (buflen < 2)
          return too_short();
  	    n = ((n - 192) << 8) + buffer[i++] + 192;
  	  }
  
      if (buflen < n)
  			return too_short();
  
      var critical = 0;
  
      type = buffer[i];
      if (type & 0x80)
  	  {
  	    type &= 0x7f;
  	    critical = 1;
  	  }
      else
  	    critical = 0;
  
  		if (reqtype == PGP.SIGSUBPKT.TEST_CRITICAL)
  		{
  	  	if (critical)
  	  	{
  	  	  if (n - 1 > buflen + 1)
  					return too_short();
  	  	  //if (!can_handle_critical (buffer + 1, n - 1, type))
  				//{
  				//logger.error(sprintf("subpacket of type %d has " +
  				//											"critical bit set\n"), type);
  			  //return null;	/* This is an error.  */
  				//}
  	    }
  		}
      else if (reqtype < 0) /* List packets.  */
      {
        var hashed = (reqtype == PGP.SIGSUBPKT.LIST_HASHED);
  	    this.dump_sig_subpkt ( hashed , type, buffer.slice(i + 1), n - 1);
      }
      else if (type == reqtype) /* Found.  */
  	  {
        i++;
  	    if (n > buflen)
  			  return too_short();
  	    offset = this.parse_one_sig_subpkt (buffer.slice(i), n - 1, type); //XXX n-1
  	    switch (offset)
  	    {
  	      case -2:
  	        logger.error("subpacket of type %d too short\n", type);
  	        return null;
  	      case -1:
  	        return null;
  	      default:
  	        break;
  	    }
  	    return buffer.slice(i + offset, i + offset + n - 1);
  	  }
      i += n;
    }
  
    if (reqtype == PGP.SIGSUBPKT.TEST_CRITICAL) {
      return buffer;  /* Used as True to indicate that there is no. */
    }
  
    /* Critical bit we don't understand. */
    return null;	/* End of packets; not found.  */
  
  }
  
  parse_compressed: function(inp, pkttype, pktlen, pkt, new_ctb) {
  
    /* PKTLEN is here 0, but data follows (this should be the last
       object in a file or the compress algorithm should know the
       length).  */
  
    pkt.algorithm = inp.get();
    pkt.pkttype = pkttype;
    pkt.pktlen = pktlen;
    pkt.len = 0;			/* not used */
    pkt.new_ctb = new_ctb;
    pkt.buf = inp.read_rest();
    logger.debug(":compressed packet: algo=%d\n", pkt.algorithm);
    return 0;
  },
  parse_trust: function(inp, pkttype, pktlen, pkt) {
    var c;
    if (pktlen) {
      c = inp.get();
      pktlen--;
      pkt.ring_trust = { };
      pkt.ring_trust.trustval = c;
      pkt.ring_trust.sigcache = 0;
      if (!c && pktlen == 1) {
  	    c = inp.get();
  	    pktlen--;
  	    /* We require that bit 7 of the sigcache is 0 (easier eof
                 handling).  */
  	    if (!(c & 0x80))
  	      pkt.ring_trust.sigcache = c;
  	  }
  	  logger.debug(":trust packet: flag=%d sigcache=%d\n",
                      pkt.ring_trust.trustval,
                      pkt.ring_trust.sigcache);
    }
    else {
  	  logger.debug(":trust packet: empty\n");
    }
    inp.skip_rest(pktlen);
  },
  parse_plaintext: function(inp, pkttype, pktlen, pkt, new_ctb, partial) {
    var rc = 0;
    var mode, namelen;
    var pt = {};
    var c, i;
  
    if (!partial && pktlen < 6)
      throw { 
              msg: sprintf("packet(%d) too short (%d)\n", pkttype, pktlen),
              rc: PGP.ERR.INV_PACKET
            };
  
    mode = inp.get();
    if (pktlen)
      pktlen--;
    namelen = inp.get();
    if (pktlen)
      pktlen--;
    /* Note that namelen will never exceed 255 bytes. */
    pkt.name = "";
    pkt.new_ctb = new_ctb;
    pkt.mode = mode;
    pkt.namelen = namelen;
    pkt.is_partial = partial;
  
    for (i = 0; pktlen > 4 && i < namelen; pktlen--, i++)
    {
      pkt.name += String.fromCharCode(inp.get());
    }
  
    pkt.timestamp = inp.read32();
    if (pktlen)
      pktlen -= 4;
    pkt.len = pktlen;
    pkt.buf = misc.atos(inp.read_len(pktlen));
    pktlen = 0;
  
    logger.debug(":literal data packet:\n" +
                  "\tmode %c (%X), created %u, name=%s\"",
                    mode >= ' ' && mode < 'z' ? mode : '?', mode,
                    pkt.timestamp, pkt.name
                );
    return rc;
  },
  parse_onepass_sig: function(inp, pkttype, pktlen, ops) {
    var version;
    var rc = 0;
  
    if (pktlen < 13)
      throw { 
              msg: sprintf("packet(%d) too short\n", pkttype),
              rc: PGP.ERR.INV_PACKET
            }
  
    version = inp.get();
  
    if (version != 3)
      throw {
              msg: sprintf("onepass_sig with unknown version %d\n", version),
              rc: PGP.ERR.INV_PACKET
            }
  
    ops.sig_class = inp.get();
    pktlen--;
    ops.digest_algo = inp.get();
    pktlen--;
    ops.pubkey_algo = inp.get();
    pktlen--;
    ops.keyid = "";
    for (var i=8;i;i--)
      ops.keyid += String.fromCharCode(inp.get());
  
    pktlen -= 8;
    ops.last = inp.get();
    pktlen--;
    logger.debug(
                  ":onepass_sig packet: keyid %s\n" +
                  "\tversion %d, sigclass 0x%02x, digest %d, pubkey %d, " +
                  "last=%d\n",
                  misc.stohex(ops.keyid).toUpperCase(),
                  version, ops.sig_class,
                  ops.digest_algo, ops.pubkey_algo, ops.last
                );
  
    inp.skip_rest();
    return rc;
  },
  parse_encrypted: function(inp, pkttype, pktlen, ed, new_ctb, partial) {
    var rc = 0;
  //      ed = {};
    var orig_pktlen = pktlen;
  
    /* ed->len is set below.  */
    ed.extralen = 0;  /* Unknown here; only used in build_packet.  */
    ed.buf = null;
    ed.new_ctb = new_ctb;
    ed.is_partial = partial;
  
    if (pkttype == PGP.PKT.ENCRYPTED_MDC)
    {
      var version = inp.get();
      if (orig_pktlen)
  	    pktlen--;
  
      if (version != 1)
  	  {
        logger.error("encrypted_mdc packet with unknown version %d", version);
  	    return PGP.ERR.INV_PACKET;
      }
      ed.mdc_method = 2; //DIGEST_ALGO_SHA1=2
    }
    else
      ed.mdc_method = 0;
  
    /* A basic sanity check.  We need at least an 8 byte IV plus the 2
       detection bytes.  Note that we don't known the algorithm and thus
       we may only check against the minimum blocksize.  */
    if (orig_pktlen && pktlen < 10)
    {
      /* Actually this is blocksize+2.  */
      logger.error("packet(%d) too short\n", pkttype);
      return PGP.ERR.INV_PACKET;
    }
  
    /* Store the remaining length of the encrypted data (i.e. without
       the MDC version number but with the IV etc.).  This value is
       required during decryption.  */
    ed.len = pktlen;
  
    if (orig_pktlen)
  	  logger.debug(":encrypted data packet:\n\tlength: %d", orig_pktlen);
    else
  	  logger.debug(":encrypted data packet:\n\tlength: unknown");
  
    if (ed.mdc_method)
  	  logger.debug("\tmdc_method: %d\n", ed.mdc_method);
  
  
    ed.buf = inp.read(ed);
  
    return rc;
  },
  parse_pubkeyenc: function(inp, pkttype, pktlen, packet) {
    var rc = 0;
    var i, ndata;
    var k = packet;
  
    if (pktlen < 12) {
      logger.error ("packet(%d) too short\n", pkttype);
      return PGP.ERR.INV_PACKET;
    }
    k.version = inp.get();
    pktlen--;
    if (k.version != 2 && k.version != 3)
    {
      logger.error ("packet(%d) with unknown version %d\n", pkttype, k.version);
      return PGP.ERR.INV_PACKET;
    }
  
    k.keyid = "";
    for (var i=8;i;i--)
      k.keyid += String.fromCharCode(inp.get());
  
    pktlen -= 8;
    k.pubkey_algo = inp.get();
    pktlen--;
    k.throw_keyid = 0;  /* Only used as flag for build_packet.  */
    k.data = [];
    logger.debug(":pubkey enc packet: version %d, algo %d, keyid %s",
                  k.version, k.pubkey_algo, misc.stohex(k.keyid).toUpperCase());
  
    var ndata = misc.pubkey_get_nenc (k.pubkey_algo);
    if (!ndata)
    {
      logger.error("\tunsupported algorithm %d\n", k.pubkey_algo);
      return PGP.ERR.INV_PACKET;
    }
    else
    {
      for (i = 0; i < ndata; i++)
      {
        if (k.pubkey_algo == PGP.PUBKEY.ALGO.ECDH && i == 1)
          {
            return PGP.ERR.NOT_IMPLEMENTED;
            //size_t n;
  	        //rc = read_size_body (inp, pktlen, &n, k>data+i);
            //pktlen -= n;
          }
        else
        {
  	      n = pktlen;
          k.data[i] = misc.mpi_read (inp, pktlen);
          pktlen -= k.data[i].length;
          if (!k.data[i])
            return PGP.ERR.INV_PACKET;
        }
      }
    }
    return rc;
  },
  parse_signature: function(inp, pkttype, pktlen, sig) {
    var md5_len = 0,
    		n,
    		is_v4 = 0,
    		rc = 0,
    		i, ndata;
  
    if (pktlen < 16)
    {
      logger.error("packet(%d) too short\n", pkttype);
    	inp.skip_rest (pktlen);
      return PGP.ERR.INV_PACKET;
    }
  
    sig.version = inp.get();;
    pktlen--;
  
    if (sig.version == 4)
      is_v4 = 1;
  
    if (sig.version == 3)
    {
      logger.error("packet(%d) Version %d\n signature packet not implemented", pkttype, sig.version);
  		inp.skip_rest ( pktlen );
      return PGP.ERR.NOT_IMPLEMENTED;
    }
    else if (sig.version != 2 && sig.version != 3 && sig.version != 4)
    {
      logger.error("packet(%d) with unknown version %d\n", pkttype, sig.version);
  		inp.skip_rest(pktlen);
      return PGP.ERR.INV_PACKET;
    }
  
    sig.sig_class = inp.get();
    pktlen--;
    sig.pubkey_algo = inp.get();
    pktlen--;
    sig.digest_algo = inp.get();
    pktlen--;
  
  	sig.flags = {};
    sig.flags.exportable = 1;
    sig.flags.revocable = 1;
  
    if (is_v4) /* Read subpackets.  */
    {
      n = inp.read16();
      pktlen -= 2;  /* Length of hashed data. */
      if (n > 10000)
  	  {
  	    logger.error("signature packet: hashed data too long\n");
      	inp.skip_rest(pktlen);
        return PGP.ERR.INV_PACKET;
  	  }
      if (n)
  	  {
  	    sig.hashed = {};
  	    sig.hashed.len = n;
  	    inp.read(sig.hashed);
  	    pktlen -= n;
  	  }
      n = inp.read16();
      pktlen -= 2;  /* Length of unhashed data.  */
      if (n > 10000)
  	  {
  	    logger.error("signature packet: unhashed data too long\n");
      	inp.skip_rest(pktlen);
  	    return PGP.ERR.INV_PACKET;
  	  }
      if (n)
  	  {
  	  	sig.unhashed = {};
  	    sig.unhashed.len = n;
  	    inp.read(sig.unhashed, n);
       	pktlen -= n;
  	  }
    }
  
    if (pktlen < 5)  /* Sanity check.  */
    {
      logger.error("packet(%d) too short\n", pkttype);
  		inp.skip_rest ( pktlen, 0);
    	return PGP.ERR.INV_PACKET;
    }
  
    sig.digest_start = [ inp.get(), inp.get() ];
    pktlen -= 2;
  
    if ( sig.pubkey_algo )  /* Extract required information.  */
    {
  
        /* Set sig->flags.unknown_critical if there is a critical bit
         * set for packets which we do not understand.  */
      if (!this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.TEST_CRITICAL)
          || !this.parse_sig_subpkt (sig.unhashed, PGP.SIGSUBPKT.TEST_CRITICAL))
  			sig.flags.unknown_critical = 1;
  
      var p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.SIG_CREATED);
      
  
      if (p)
  			sig.timestamp = string_to_u32(p);
      else if (!(sig.pubkey_algo >= 100 && sig.pubkey_algo <= 110))
  			logger.info("signature packet without timestamp\n");
  
      p = this.parse_sig_subpkt2(sig, PGP.SIGSUBPKT.ISSUER);
      if (p)
  	  {
        sig.keyid = misc.atos(p); 
  	  }
      else if (!(sig.pubkey_algo >= 100 && sig.pubkey_algo <= 110))
  			logger.info("signature packet without keyid\n");
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.KEY_EXPIRE); 
      if (p && string_to_u32 (p))
  			sig.expiredate = sig.timestamp + string_to_u32 (p);
  
      sig.flags = { expired: 0, policy_url: 0, notations: 0,
                    pref_ks: 0, revocable: 1, key_flags: 0 };
  
      if (p && string_to_u32(p) && sig.expiredate >= sig.timestamp)
  			sig.flags.expired = 1;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.POLICY);
      if (p)
  			sig.flags.policy_url = 1;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.PREF_KS);
      if (p)
  			sig.flags.pref_ks = 1;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.NOTATION);
      if (p)
  			sig.flags.notation = 1;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.REVOCABLE);
      if (p && p == 0)
  			sig.flags.revocable = 0;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.KEY_FLAGS);
      if (p && p.length)
  		  sig.key_flags = p[0];
  
  XXX
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.PREF_SYM);
      if (p && p.length)
  		  sig.pref_sym = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.REV_KEY);
      if (p && p.length)
  		  sig.rev_key = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.PREF_HASH);
      if (p && p.length)
  		  sig.pref_hash = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.PREF_COMPR);
      if (p && p.length)
  		  sig.pref_compr = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.KS_FLAGS);
      if (p && p.length)
  		  sig.ks_flags = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.PREF_KS);
      if (p && p.length)
  		  sig.pref_flags = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.PRIMARY_UID);
      if (p && p.length)
  		  sig.primary_uid = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.POLICY);
      if (p && p.length)
  		  sig.policy = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.SIGNERS_UID);
      if (p && p.length)
  		  sig.signers_uid = p;
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.REVOC_REASON);
      if (p && p.length)
      {
  		  sig.revoc_reason = p[0];
  		  sig.revoc_comment = misc.atos(p.slice(1));
      }
  
      p = this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.TRUST);
      if (p && p.length == 2)
  	  {
  	    sig.trust_depth = p[0];
  	    sig.trust_value = p[1];
  
  	    /* Only look for a regexp if there is also a trust
  	       subpacket. */
  	    sig.trust_regexp =
  	      this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.REGEXP);
  
  		}
  
        /* We accept the exportable subpacket from either the hashed or
           unhashed areas as older versions of gpg put it in the
           unhashed area.  In theory, anyway, we should never see this
           packet off of a local keyring. */
  
      p = this.parse_sig_subpkt (sig, PGP.SIGSUBPKT.EXPORTABLE);
      if (p && p == 0)
  			sig.flags.exportable = 0;
  
        /* Find all revocation keys.  */
      if (sig.sig_class == 0x1F)
  		  this.parse_revkeys (sig);
      
      logger.debug(":signature packet: algo %d, keyid %s\n" +
                  "\tversion %d, created %d, md5len %d, sigclass 0x%02x\n" +
                  "\tdigest algo %d, begin of digest %02x %02x",
                  sig.pubkey_algo,
                  misc.stohex(sig.keyid).toUpperCase(),
                  sig.version, sig.timestamp, md5_len, sig.sig_class,
                  sig.digest_algo, sig.digest_start[0], sig.digest_start[1]);
      if (is_v4)
      {
        this.parse_sig_subpkt (sig.hashed, PGP.SIGSUBPKT.LIST_HASHED);
        this.parse_sig_subpkt (sig.unhashed, PGP.SIGSUBPKT.LIST_UNHASHED);
      }
    }
  
    ndata = misc.pubkey_get_nsig (sig.pubkey_algo);
  
    if (!ndata)
    {
  	  logger.info("\tunknown algorithm %d\n", sig.pubkey_algo);
  	  rc = PGP.ERR.INV_PACKET;
    }
    else
    {
      sig.data = [ ];
      for (i = 0; i < ndata; i++)
  	  {
  	    sig.data[i] = misc.mpi_read (inp, pktlen);
  	    pktlen -= sig.data.length;
  	    //mpi_print (listfp, sig->data[i], mpi_print_mode);
  
  	    if (!sig.data[i]) {
  	    	rc = PGP.ERR.INV_PACKET;
          break;
        }
  	  }
    }
  
    if (rc != 0) {
      inp.skip_rest ( pktlen );
    }
    return rc;
  },
  /* Find all revocation keys.  Look in hashed area only.  */
  parse_revkeys: function(sig) {
    var revkey = { };
    var seq = 0;
    var len;
  
    if (sig.sig_class != 0x1F)
      return;
  
    //while ((revkey =
  	//  (struct revocation_key *) enum_sig_subpkt (sig->hashed,
  	//					     SIGSUBPKT_REV_KEY,
  	//					     &len, &seq, NULL)))
    //  {
    //    if (len == sizeof (struct revocation_key)
    //        && (revkey->class & 0x80))  /* 0x80 bit must be set.  */
  	//{
  	//  sig->revkey = xrealloc (sig->revkey,
  	//			  sizeof (struct revocation_key *) *
  	//			  (sig->numrevkeys + 1));
  	//  sig->revkey[sig->numrevkeys] = revkey;
  	//  sig->numrevkeys++;
  	//}
    //  }
  },
  parse_user_id: function(inp, pkttype, pktlen, pkt) {
    if (pktlen > 2048)
    {
      logger.error("packet(%d) too large\n", pkttype);
      inp.skip_rest ( pktlen);
      return PGP.ERR.INVALID_PACKET;
    }
  
    pkt.len = pktlen;
    pkt.ref = 1;
  
    var p = "";
    for (; pktlen; pktlen--)
      p += String.fromCharCode(inp.get());
  
    pkt.name = p;
  
    logger.debug(":user ID packet: \"%s\"", pkt.name);
    return 0;
  },
  /* Attribute subpackets have the same format as v4 signature
     subpackets.  This is not part of OpenPGP, but is done in several
     versions of PGP nevertheless.  */
  parse_attribute_subpkts: function(uid) {
    var n = 0;
    var count = 0;
    var buffer = uid.attrib_data;
    var buflen = uid.attrib_len;
    var attribs = [];
    var type;
    var i=0;
  
    try {
      while (buflen)
      {
        n = buffer[i++];
        buflen--;
        if (n == 255)  /* 4 byte length header.  */
  	    {
  	      if (buflen < 4)
  	        throw("TOO_SHORT");
  	      n = (buffer[1] << 24) | (buffer[2] << 16)
  	        | (buffer[3] << 8) | buffer[4];
          n = n >>> 0;
          i+=4;
  	      buflen -= 4;
  	    }
        else if (n >= 192)  /* 2 byte special encoded length header.  */
  	    {
  	      if (buflen < 2)
  	        throw("TOO_SHORT");
  	      n = ((n - 192) << 8) + buffer[i++] + 192;
  	      buflen--;
  	    }
        if (buflen < n)
  	      throw("TOO_SHORT");
  
        type = buffer[i++];
        buflen--;
        n--;
  
        attribs[count] = { };
        attribs[count].type = type;
        attribs[count].data = buffer.slice(i,i+n);
        attribs[count].len = n;
        buflen -= n;
        count++;
      }
      uid.attribs = attribs;
      uid.numattribs = count;
      return count;
    }
    catch (e)
    {
      logger.info("buffer shorter than attribute subpacket\n");
      return count;
    }
  },
  make_attribute_uidname: function(uid, max_namelen) {
    //assert (max_namelen > 70);
    if (uid.numattribs <= 0)
      uid.name = sprintf("[bad attribute packet of size %u]", 
                                  uid.attrib_len);
    else if (uid.numattribs > 1)
      uid.name = sprintf("[%d attributes of size %u]", 
                                  uid.numattribs, uid.attrib_len);
    else
    {
      /* Only one attribute, so list it as the "user id" */
      const ATTRIB_IMAGE = 1;
      if (uid.attribs[0].type == ATTRIB_IMAGE) {
        var len;
  	    if (photoid.parse_image_header(uid.attribs[0], len)) {
          uid.attribs[0].image = base64Encode(misc.atos(uid.attribs[0].data.slice(16)));
  	      uid.name = getStr("image_size", 
                       photoid.image_type_to_string (uid.attribs[0].type, 1), uid.attribs[0].len);
        }
  	    else
  	      uid.name = getStr("invalid_image");
  	  }
      else {
        uid.name = getStr("unknown_attrib", uid.attribs[0].len);
      }
    }
  },
  parse_attribute: function(inp, pkttype, pktlen, pkt) {
    pkt.ref = 1;
    pkt.attrib_len = pktlen;
  
    var p = [];
  
    for (; pktlen; pktlen--)
      p.push(inp.get());
  
    pkt.attrib_data = p;
  
    /* Now parse out the individual attribute subpackets.  This is
       somewhat pointless since there is only one currently defined
       attribute type (jpeg), but it is correct by the spec. */
    this.parse_attribute_subpkts (pkt);
    var EXTRA_UID_NAME_SPACE = 70;
    this.make_attribute_uidname (pkt, EXTRA_UID_NAME_SPACE);
  
    logger.debug( ":attribute packet: " + pkt.name);
    return 0;
  },
  parse_key: function(inp, pkt) {
    var version, algorithm,
        timestamp, expiredate, max_expiredate,
        npkey, nskey,
        is_v4 = 0,
        rc = 0;
  
    var pktlen = pkt.pktlen;
    var pkttype = pkt.pkttype;
  
  	version = inp.get(); 
    pktlen--;
  
    if (pkttype == PGP.PKT.PUBLIC_SUBKEY && version == '#')
    {
      /* Early versions of G10 used the old PGP comments packets;
       * luckily all those comments are started by a hash.  */
  	  logger.debug(":rfc1991 comment packet: \"");
      var cbuf = '';
  	  for (; pktlen; pktlen--)
  	  {
  	    var c;
  	    c = inp.get();
  
  	    if (c >= ' ' && c <= 'z')
  		    cbuf += c;
  	    else
          cbuf += parseInt(c).toString(16);
  
  	  }
      logger.debug(cbuf);
      inp.skip(pktlen);
      return 0;
    }
    else if (version == 4)
      is_v4 = 1;
    else if (version != 2 && version != 3)
    {
      logger.error("packet(%d) with unknown version %d\n", pkttype, version);
      return PGP.ERR.INV_PACKET;
    }
  
    if (pktlen < 11)
    {
      logger.error("packet(%d) too short\n", pkttype);
      return PGP.ERR.INV_PACKET;
    }
  
    timestamp = inp.read32();
    pktlen -= 4;
  
    if (is_v4)
    {
      expiredate = 0;		/* have to get it from the selfsignature */
      max_expiredate = 0;
    }
    else
    {
      ndays = inp.read16();
      pktlen -= 2;
      if (ndays)
  			expiredate = timestamp + ndays * 86400;
      else
  			expiredate = 0;
  
      max_expiredate = expiredate;
    }
    algorithm = inp.get();
    pktlen--;
    logger.debug(":%s key packet:\n" + 
                 "\tversion %d, algo %d,\n\tcreated %s,\n\texpires %s",
                 pkttype == PGP.PKT.PUBLIC_KEY ? "public" :
                 pkttype == PGP.PKT.SECRET_KEY ? "secret" :
                 pkttype == PGP.PKT.PUBLIC_SUBKEY ? "public sub" :
                 pkttype == PGP.PKT.SECRET_SUBKEY ? "secret sub" : "??",
                 version, algorithm, timestamp, expiredate);
  
    pkt.timestamp = timestamp;
    pkt.expiredate = expiredate;
    pkt.max_expiredate = max_expiredate;
    pkt.version = version;
    pkt.flags = { };
    pkt.flags.primary = (pkttype == PGP.PKT.PUBLIC_KEY || pkttype == PGP.PKT.SECRET_KEY);
    pkt.pubkey_algo = algorithm;
  
    nskey = misc.pubkey_get_nskey (algorithm);
    npkey = misc.pubkey_get_npkey (algorithm);
  
    if (!npkey)
    {
  		logger.error("\tunknown algorithm %d\n", algorithm);
      return PGP.ERR.INV_PACKET;
    }
    else
    {
      pkt.pkey = [];
      for (var i = 0; i < npkey; i++)
      {
        pkt.pkey[i] = misc.mpi_read(inp, pktlen); 
  		
        if (!pkt.pkey[i]) 
        {
          return PGP.ERR.INV_PACKET;
        }
  
        pktlen -= pkt.pkey[i].length;
  	  }
  	}
  
    var ski = pkt.ski = { usage: 0 };
    ski.s2k = { mode: 0 };
    ski.is_protected = 0;
  
  
    if (pkttype == PGP.PKT.SECRET_KEY || pkttype == PGP.PKT.SECRET_SUBKEY)
    {  
      pkt.skey = [];
  
      ski.usage = inp.get();
      pktlen--;
      if (ski.usage) 
      {
        ski.is_protected = 1;
        ski.s2k.count = 0;
        if (ski.usage == 254 || ski.usage == 255) 
        {
          if (pktlen < 3) 
          {
            return PGP.ERR.INV_PACKET;
          }
  
          ski.sha1chk = (ski.usage == 254);
          ski.algo = inp.get();
          pktlen--;
  
          ski.s2k.mode = inp.get();
          pktlen--;
  	      ski.s2k.hash_algo = inp.get();
  	      pktlen--;
  
          switch (ski.s2k.mode)
          {
  		      case 1:
  		      case 3:
              var temp = [ ];
  		        for (i = 0; i < 8 && pktlen; i++, pktlen--)
  		          temp.push(inp.get());
              ski.s2k.salt = temp;
  		        break;
  		    }
  
          /* check the mode.  */
  	      switch (ski.s2k.mode)
  		    {
  		      case 0:
  		        logger.debug("\tsimple S2K");
  		        break;
  		      case 1:
  		        logger.debug("\tsalted S2K");
  		        break;
  		      case 3:
  		        logger.debug("\titer+salt S2K");
  		        break;
  		      case 1001:
  		        logger.debug("\tgnu-dummy S2K");
  		        break;
  		      case 1002:
  		        logger.debug("\tgnu-divert-to-card S2K");
  		        break;
  		      default:
  		        logger.debug("\tunknown %sS2K %d\n",
                                        ski.s2k.mode < 1000 ? "" : "GNU ",
                                        ski.s2k.mode);
  
  		        return PGP.ERR.INV_PACKET;
  		    }
        }
    		logger.debug(", algo: %d,%s hash: %d",
                      ski.algo,
                      ski.sha1chk ? " SHA1 protection,"
                                  : " simple checksum,", ski.s2k.hash_algo);
    
    		if (ski.s2k.mode == 1 || ski.s2k.mode == 3)
    		{
    		  logger.debug(", salt: ");
    		}
        /* Read remaining protection parameters.  */
    	  if (ski.s2k.mode == 3)
    		{
    		  if (pktlen < 1)
    		  {
    		    return PGP.ERR.INV_PACKET;
    		  }
    		  ski.s2k.count = inp.get();
    		  pktlen--;
    		  logger.debug("\tprotect count: %d (%d)\n",
                                    //S2K_DECODE_COUNT ((ulong)ski->s2k.count),
                                    0,
                                    ski.s2k.count);
    		}
    	  else if (ski.s2k.mode == 1002)
    		{
    		  /* Read the serial number. */
    		  if (pktlen < 1)
    		  {
    		    return PGP.ERR.INV_PACKET;
    		  }
    		  snlen = inp.get();
    		  pktlen--;
    		  if (pktlen < snlen || snlen == -1)
    		  {
    		    return PGP_ERR_INV_PACKET;
    		  }
    		}
    	  else /* Old version; no S2K, so we set mode to 0, hash MD5.  */
    	  {
          /* Note that a ski->algo > 110 is illegal, but I'm not
             erroring on it here as otherwise there would be no
             way to delete such a key.  */
    	    ski.s2k.mode = 0;
    	    ski.s2k.hash_algo = PGP.DIGEST_ALGO_MD5;
    		  logger.debug("protect algo: %d  (hash algo: %d)",
                              ski.algo, ski.s2k.hash_algo);
    	  }
    
    	  /* It is really ugly that we don't know the size
    	   * of the IV here in cases we are not aware of the algorithm.
    	   * so a
    	   *   ski->ivlen = cipher_get_blocksize (ski->algo);
    	   * won't work.  The only solution I see is to hardwire it.
    	   * NOTE: if you change the ivlen above 16, don't forget to
    	   * enlarge temp.  */
    	  ski.ivlen = misc.openpgp_cipher_blocklen (ski.algo);
    
    	  if (ski.s2k.mode == 1001)
    	    ski.ivlen = 0;
    	  else if (ski.s2k.mode == 1002)
    	    ski.ivlen = snlen < 16 ? snlen : 16;
    
    	  if (pktlen < ski.ivlen)
    	  {
            return PGP.ERR.INV_PACKET;
    	  }
    
        var temp = [ ];
    	  for (i = 0; i < ski.ivlen && pktlen; i++, pktlen--)
    	    temp[i] = inp.get();
    
    	  logger.debug( ski.s2k.mode == 1002 ? "\tserial-number: "
                                           : "\tprotect IV: " );
    	  for (i = 0; i < ski.ivlen; i++)
        {
    		  logger.debug(" %02x", temp[i]);
    	  }
        ski.iv = temp;
    	}
    /* It does not make sense to read it into secure memory.
     * If the user is so careless, not to protect his secret key,
     * we can assume, that he operates an open system :=(.
     * So we put the key into secure memory when we unprotect it. */
      if (ski.s2k.mode == 1001 || ski.s2k.mode == 1002)
    	{
    	  /* Better set some dummy stuff here.  */
    //	  pk->pkey[npkey] = gcry_mpi_set_opaque (NULL,
    //						 xstrdup ("dummydata"),
    //						 10 * 8);
    	  pktlen = 0;
    	}
    
      else if (is_v4 && ski.is_protected)
      {
    	  /* Ugly: The length is encrypted too, so we read all stuff
    	   * up to the end of the packet into the first SKEY
    	   * element.  */
    
    	  pkt.skey[0] = inp.readString(pktlen);
    	  pktlen = 0;
        logger.debug("\tskey[%d]: [v4 protected]\n", npkey);
      }
      else
      {
        /* The v3 method: The mpi length is not encrypted.  */
    	  for (i = 0; i < nskey - npkey; i++)
    	  {
    	    if (ski.is_protected)
    	    {
    	      //pk->pkey[i] = read_protected_v3_mpi (inp, &pktlen);
    	      //if (list_mode)
    	      logger.debug( "\tskey[%d]: [v3 protected]\n", i);
            logger.error("Not implemented");
            return PGP.ERROR.INV_PACKET;
    	    }
    	    else
    	    {
    	      var n = pktlen;
    	      pkt.skey[i] = misc.mpi_read(inp, pktlen);
    	      pktlen -= pkt.skey[i].length;
    	      logger.debug("\tskey[%d]: (%d bits)", i, pkt.skey[i].length);
    	    }
    
    	    if (!pkt.skey[i])
    	  	  return PGP.ERR.INV_PACKET;
        }
    
    	  ski.csum = inp.read16();
    	  pktlen -= 2;
        logger.debug("\tchecksum: %x", ski.csum);
      }
    }
    return 0;
  },
  
  /*
   * Parse packet. 
   */
  parse: function(inp, pkt) {
    var rc = 0, 
        partial = 0,
        pktlen = 0,
        pkttype,
        ctb;
  
  
    if ((ctb = (inp.get())) == -1)
    {
      return -1;
    }
  
    if (!(ctb & 0x80))
    {
      logger.error(": invalid packet (ctb=%02x)", inp.where());
      return PGP.ERR.INV_PACKET;
    }
  
    var new_ctb = !!(ctb & 0x40);
  
    if (new_ctb)
    {
      pkttype = ctb & 0x3f;
      var c;
      if ((c = inp.get()) == -1)
  	  {
  	    logger.error ("%s: 1st length byte missing", inp.where());
  	    return PGP.ERR.INV_PACKET;
      }
      if (c < 192)
        pktlen = c;
      else if (c < 224)
      {
        pktlen = (c - 192) * 256;
        if ((c = inp.get()) == -1)
        {
          logger.error ("%s: 2nd length byte missing", inp.where());
          return PGP.ERR.INV_PACKET;
        }
        pktlen += c + 192;
      }
      else if (c == 255)
      {
        pktlen = inp.get() << 24;
        pktlen |= inp.get() << 16;
        pktlen |= inp.get() << 8;
        if ((c = inp.get()) == -1)
        {
          logger.error("%s: 4 byte length invalid", inp.where());
          return PGP.ERR.INV_PACKET;
        }
      }
      else /* Partial body length.  */
      {
        switch (pkttype)
        {
        case PKT_PLAINTEXT:
        case PKT_ENCRYPTED:
        case PKT_ENCRYPTED_MDC:
        case PKT_COMPRESSED:
          //iobuf_set_partial_block_mode (inp, c & 0xff);
          pktlen = 0;	/* To indicate partial length.  */
          partial = 1;
          break;
  
        default:
          logger.error("%s: partial length for invalid" +
                     " packet type %d", inp.where(), pkttype);
          return PGP.ERR.INV_PACKET;
        }
      }
    }
    else
    {
      pkttype = (ctb >> 2) & 0xf;
      var lenbytes = ((ctb & 3) == 3) ? 0 : (1 << (ctb & 3));
      if (!lenbytes)
  	  {
        pktlen = 0;
        partial = 1;
        if (pkttype != PGP.PKT.ENCRYPTED && pkttype != PGP.PKT.PLAINTEXT
            && pkttype != PGP.PKT.COMPRESSED)
        {
          logger.error("%s: indeterminate length for invalid" +
              			   " packet type %d\n", inp.where(), pkttype);
          throw "PGP.ERR.INV_PACKET";
  	    }
      }
      else
  	  {
  	    for (; lenbytes; lenbytes--)
  	    {
  	      pktlen <<= 8;
  	      pktlen |= inp.get();
  	    }
    	}
    }
  
    logger.debug("parse_packet(iob=%s): type=%d length=%d%s",
  		           inp.where() , pkttype, pktlen, new_ctb ? " (new_ctb)" : "");
  
    pkt.pktlen = pktlen;
    pkt.pkttype = pkttype;
  
    rc = PGP.ERR.UNKNOWN_PACKET;	/* default error */
  
    switch (pkttype)
    {
      case PGP.PKT.PUBLIC_KEY:
      case PGP.PKT.PUBLIC_SUBKEY:
      case PGP.PKT.SECRET_KEY:
      case PGP.PKT.SECRET_SUBKEY:
        rc = this.parse_key (inp, pkt);
        break;
     // case PKT_SYMKEY_ENC:
     //   rc = parse_symkeyenc (inp, pkttype, pktlen, pkt);
     //   break;
      case PGP.PKT.PUBKEY_ENC:
        rc = this.parse_pubkeyenc (inp, pkttype, pktlen, pkt);
        break;
      case PGP.PKT.SIGNATURE:
        rc = this.parse_signature (inp, pkttype, pktlen, pkt);
        break;
      case PGP.PKT.ONEPASS_SIG:
        rc = this.parse_onepass_sig (inp, pkttype, pktlen, pkt);
        break;
      case PGP.PKT.USER_ID:
        rc = this.parse_user_id (inp, pkttype, pktlen, pkt);
        break;
      case PGP.PKT.ATTRIBUTE:
        pkt.pkttype = pkttype = PGP.PKT.USER_ID;	/* we store it in the userID */
        rc = this.parse_attribute (inp, pkttype, pktlen, pkt);
        break;
  //    case PKT_OLD_COMMENT:
  //    case PKT_COMMENT:
  //      rc = parse_comment (inp, pkttype, pktlen, pkt);
  //      break;
      case PGP.PKT.RING_TRUST:
        this.parse_trust (inp, pkttype, pktlen, pkt);
        rc = 0;
        break;
      case PGP.PKT.PLAINTEXT:
        rc = this.parse_plaintext(inp, pkttype, pktlen, pkt, new_ctb, partial);
        break;
      case PGP.PKT.COMPRESSED:
        rc = this.parse_compressed (inp, pkttype, pktlen, pkt, new_ctb);
        break;
      case PGP.PKT.ENCRYPTED:
      case PGP.PKT.ENCRYPTED_MDC:
        rc = this.parse_encrypted (inp, pkttype, pktlen, pkt, new_ctb, partial);
        break;
      case PGP.PKT.MDC:
        pkt.pkttype = PGP.PKT.MDC;
        pkt.data = inp.read_len(pktlen);
        rc = 0;
        //rc = parse_mdc (inp, pkttype, pktlen, pkt, new_ctb);
        break;
  //    case PKT_PGP_CONTROL:
  //      rc = parse_gpg_control (inp, pkttype, pktlen, pkt, partial);
  //      break;
  //    case PKT_MARKER:
  //      rc = parse_marker (inp, pkttype, pktlen);
  //      break;
      default:
        logger.error("UNKOWN_PACKET", 
                        "Unknown packet (type=%d): skipping %d bytes ", 
                        pkttype, pktlen);
        inp.skip_rest(pktlen);
        break;
    }
    return rc;
  }
}

exports.Parser = Parser;

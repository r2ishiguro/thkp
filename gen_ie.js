var TAG_SIGNATURE = 2;
var TAG_PUBLIC_KEY = 6;
var TAG_PUBLIC_SUB_KEY = 14;
var TAG_USER_ID = 13;
var TAG_SECRET_KEY = 5;
var TAG_SECRET_SUB_KEY = 7;
var SIGTYPE_GENERIC_CERT = 0x10;
var SIGTYPE_SUBKEY_BINDING = 0x18;
var ALG_RSA = 1;
var ALG_AES128 = 7;
var ALG_SHA256 = 8;
var ALG_ZIP = 1;
var SS_CREATION_TIME = 2;
var SS_ISSUER = 16;
var SS_KEY_FLAGS = 27;
var SS_PREF_SYM = 11;
var SS_PREF_HASH = 21;
var SS_PREF_COMP = 22;
var SS_PRIMARY = 25;
var SS_FEATURES = 30;

//
// for IE
//

if (!ArrayBuffer.prototype.slice) {
	ArrayBuffer.prototype.slice = function (begin, end) {
		var len = this.byteLength;
		begin = (begin|0) || 0;
		end = end === (void 0) ? len : (end|0);
		
		// Handle negative values.
		if (begin < 0) begin = Math.max(begin + len, 0);
		if (end < 0) end = Math.max(end + len, 0);
		
		if (len === 0 || begin >= len || begin >= end) {
			return new ArrayBuffer(0);
		}
		
		var length = Math.min(len - begin, end - begin);
		var target = new ArrayBuffer(length);
		var targetArray = new Uint8Array(target);
		targetArray.set(new Uint8Array(begin, length));
		return target;
	};
}

if (!Uint8Array.prototype.slice) {
	Uint8Array.prototype.slice = function (begin, end) {
		return new Uint8Array(this.buffer.slice(begin, end));
	};
}

if (window.msCrypto) {
	var _wc = window.msCrypto.subtle;
	var wc = {
		_call: function(f, args) {
			return new Promise(function(resolve, reject) {
				op = _wc[f].apply(_wc, args);
				op.oncomplete = function(ev) {
					resolve(ev.target.result);
				};
				op.onerror = function(ev) {
//					console.log("msCrypto." + f + " failed", ev);
					reject();
				};
			});
		},
		generateKey: function(algo, extractable, usage) {
			return this._call("generateKey", arguments);
		},
		exportKey: function(algo, key) {
			return this._call("exportKey", arguments);
		},
		sign: function(algo, priv, target) {
			return this._call("sign", arguments);
		},
		digest: function(algo, data) {
			if (algo == 'SHA-1') {
				return new Promise(function(resolve, reject) {
					resolve(window.sha1.arrayBuffer(data));
				});
			}
			else
				return this._call("digest", arguments);
		},
	};
}
else {
	var _wc = window.crypto.webkitSubtle || window.crypto.subtle;
	var digest_org = _wc.digest;
	_wc.digest = function(algo, data) {
		return digest_org.call(_wc, algo, data)
			.then(function(h) {return h;})
			.catch(function(e) {
				if (algo == 'SHA-1') {
					// fall back to a JS version of SHA1 for Edge
					return window.sha1.arrayBuffer(data);
				}
				throw e;
			})
	};
	var wc = {
		_call: function(f, args) {
			return _wc[f].apply(_wc, args)
				.then(function(res) {return res;})
				.catch(function(e) {console.log(f + " caused error:", e); throw e;});
		},
		generateKey: function(algo, extractable, usage) {
			return this._call("generateKey", arguments);
		},
		exportKey: function(algo, key) {
			return this._call("exportKey", arguments);
		},
		sign: function(algo, priv, target) {
			return this._call("sign", arguments);
		},
		digest: function(algo, data) {
			return this._call("digest", arguments);
		},
		importKey: function(algo, data, opt, exportable, usage) {
			return this._call("importKey", arguments);
		},
	};
}

function Stream() {
	this.buf = new Uint8Array(128);
	this.widx = 0;
}

Stream.prototype.morebuf = function(n) {
	if (n < 128) n = 128;
	var nbuf = new Uint8Array(this.buf.length + n);
	nbuf.set(this.buf);
	this.buf = nbuf;
};
Stream.prototype.nbits = function(x) {
	var n = 1, t;
	if ((t = x >>> 16) !== 0) {
		x = t;
		n += 16;
	}
	if ((t = x >> 8) !== 0) {
		x = t;
		n += 8;
	}
	if ((t = x >> 4) !== 0) {
		x = t;
		n += 4;
	}
	if ((t = x >> 2) !== 0) {
		x = t;
		n += 2;
	}
	if ((t = x >> 1) !== 0) {
		x = t;
		n += 1;
	}
	return n;
};
Stream.prototype.putc = function(c) {
	if (this.widx >= this.buf.length)
		this.morebuf(1);
	this.buf[this.widx++] = c;
};
Stream.prototype.putn = function(n, nbytes) {
	while (--nbytes >= 0)
		this.putc((n >>> (nbytes * 8)) & 0xff);
};
Stream.prototype.puts = function(b) {
	var n = b.byteLength;
	if (n <= 0)
		return;
	if (this.widx + n > this.buf.length)
		this.morebuf(n);
	this.buf.set(new Uint8Array(b), this.widx);
	this.widx += n;
};
Stream.prototype.putmpi = function(b) {
	var a = new Uint8Array(b.byteLength + 2);
	a.set(new Uint8Array(b), 2);
	var bitsz = (b.byteLength - 1) * 8 + this.nbits(a[2]);
	a[0] = (bitsz & 0xff00) >> 8;
	a[1] = bitsz & 0xff;
	this.puts(a.buffer);
};
Stream.prototype.put64 = function(b64url) {
	var b64 = b64url.replace(/\-/g, '+').replace(/_/g, '/');
	var b = atob(b64);
	var a = new Uint8Array(b.length);
	for (var i = 0; i < b.length; i++)
		a[i] = b.charCodeAt(i);
	this.putmpi(a.buffer);
};
Stream.prototype.putpkt = function(pkt) {
	var tag = pkt.tag;
	var len = pkt.byteLength;
	this.putn(0xc0 | tag, 1);
	if (len < 192)
		this.putn(len, 1);
	else if (len < 8383) {
		this.putn(((len - 192) >>> 8) + 192, 1);
		this.putn(len - 192, 1);
	}
	else {
		this.putn(0xff, 1);
		this.putn(len, 4);
	}
	this.puts(pkt);
};
Stream.prototype.putss = function(type, val, n) {
	var len = n + 1;	// including the type octet
	if (len < 192)
		this.putn(len, 1);
	else if (len < 255) {
		this.putn(((len - 192) >>> 8) + 192, 1);
		this.putn(len - 192, 1);
	}
	else {
		this.putn(0xff, 1);
		this.putn(len, 4);
	}
	this.putc(type);
	switch (typeof val) {
	case "string":
		for (var i = 0; i < n; i++)
			this.putc(val.charCodeAt(i));
		break;
	case "number":
		this.putn(val, n);
		break;
	default:
		if (val instanceof ArrayBuffer)
			this.puts(val);
		else
			throw new Error("unknown type");
	}
};
Stream.prototype.flush = function() {
	return this.buf.slice(0, this.widx).buffer;
};

		
function checksum_skey(mpis)
{
	var sum = 0;
	var a = new Uint8Array(mpis);
	for (var i = 0; i < a.length; i++)
		sum = (sum + a[i]) & 0xffff;
	return sum;
}

function packetize(tag, param)
{
	var p = new Stream();
	switch (tag) {
	case TAG_PUBLIC_KEY:
	case TAG_PUBLIC_SUB_KEY:
	case TAG_SECRET_KEY:
	case TAG_SECRET_SUB_KEY:
		p.putn(4, 1);	// version
		p.putn(Date.now() / 1000, 4);	// creation time
		p.putn(ALG_RSA, 1);	// public key algorithm
		p.put64(param.n);
		p.put64(param.e);
		if (tag == TAG_SECRET_KEY || tag == TAG_SECRET_SUB_KEY) {
			p.putn(0, 1);		// not encrypted
			ss = new Stream();
			ss.put64(param.d);
			ss.put64(param.q);
			ss.put64(param.p);
			ss.put64(param.qi);
			var sk = ss.flush();
			p.puts(sk);
			p.putn(checksum_skey(sk), 2);
		}
		break;
	case TAG_USER_ID:
		var utf8 = unescape(encodeURIComponent(param));
		var userid = new Uint8Array(utf8.length);
		for (var i = 0; i < utf8.length; i++)
			userid[i] = utf8.charCodeAt(i);
		p.puts(userid.buffer);
		break;
	}
	var pkt = p.flush();
	pkt.tag = tag;
	return pkt;
}

function tbsform(pkt)
{
	var p = new Stream();
	switch (pkt.tag) {
	case TAG_PUBLIC_KEY:
	case TAG_PUBLIC_SUB_KEY:
		p.putc(0x99);
		p.putn(pkt.byteLength, 2);
		p.puts(pkt);
		break;
	case TAG_USER_ID:
		p.putc(0xb4);
		p.putn(pkt.byteLength, 4);
		p.puts(pkt);
		break;
	}
	return p.flush();
}

function sign(key, stype, data)
{
	var hs = new Stream();	// hashed sub packets
	hs.putss(SS_CREATION_TIME, Date.now() / 1000, 4);	// creation time
	hs.putss(SS_ISSUER, key.fingerprint.slice(key.fingerprint.byteLength - 8), 8);	// issuer key ID
	if (stype == SIGTYPE_GENERIC_CERT) {
		hs.putss(SS_KEY_FLAGS, 0x03, 1);		// key flags (certify, sign)
		hs.putss(SS_PREF_SYM, ALG_AES128, 1);	// preferred symmetric algorithms (AES128 only)
		hs.putss(SS_PREF_HASH, ALG_SHA256, 1);	// preferred hash algorithms (SHA256 only)
		hs.putss(SS_PREF_COMP, ALG_ZIP, 1);	// preferred compression algorithms (ZIP only)
		hs.putss(SS_PRIMARY, 1, 1);		// primary user ID = true
		hs.putss(SS_FEATURES, 0x1, 1);		// feature: modification detection
	}
	else {
		hs.putss(SS_KEY_FLAGS, 0x0c, 1);		// key flags (encrypt communications and storage)
	}
	subpkt = hs.flush();
	var p = new Stream();
	p.putn(4, 1);	// version
	p.putn(stype, 1);	// signature type
	p.putn(ALG_RSA, 1);	// public key algorithm
	p.putn(ALG_SHA256, 1);	// hash algorithm
	// hashed subpackets
	p.putn(subpkt.byteLength, 2);
	p.puts(subpkt);
	var sigpkt = p.flush();
	// no unhashed subpackets
	p.putn(0, 2);
	// 5.2.3 "The concatenation of the data being signed and the signature data from the version number through the hashed subpacket data (inclusive) is hashed
	var ss = new Stream();
	data.forEach(function(d) {ss.puts(tbsform(d));});
	ss.puts(sigpkt);
	// trailer
	ss.putc(4);
	ss.putc(0xff);
	ss.putn(sigpkt.byteLength, 4);
	tbs = ss.flush();
	return wc.digest('SHA-256', tbs)
		.then(function(h) {
			// hashed just for the first 16 bits digest, webcrypt sign() calculates hash on its own
			p.puts(h.slice(0, 2));
			return wc.sign({name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, key.signingKey, tbs);
		})
		.then(function(sig) {
			p.putmpi(sig);
			var pkt = p.flush();
			pkt.tag = TAG_SIGNATURE;
			return pkt;
		});
}

function _generateKey(tag, opt, usage)
{
	return wc.generateKey(opt, true, usage)
		.then(function(keypair) {
			return wc.exportKey('jwk', keypair.privateKey)
				.then(function(jwk) {
					if (jwk instanceof ArrayBuffer)
						jwk = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(jwk)));
					return {
						tag: tag,
						pub: packetize(tag, jwk),
						priv: packetize(tag == TAG_PUBLIC_KEY ? TAG_SECRET_KEY : TAG_SECRET_SUB_KEY, jwk),
						signingKey: keypair.privateKey,
						jwk: jwk,
					};
				})
		})
}

function generateKey(tag)
{
	var opt = {
		name: 'RSASSA-PKCS1-v1_5',
		modulusLength: 2048,
		publicExponent: new Uint8Array([1,0,1]),
		hash: {
			name: 'SHA-256' // not required for actual RSA keys, but for crypto api 'sign' and 'verify'
		}
	};
	var usage = ['sign', 'verify'];
	var opt2 = {
		name: 'RSA-OAEP',
		modulusLength: 2048,
		publicExponent: new Uint8Array([1,0,1]),
		hash: {
			name: 'SHA-256' // have to be 'SHA-1' for Safari 10...
		}
	};
	var usage2 = ['encrypt', 'decrypt'];

	return _generateKey(tag, opt, usage)
//		.then(function (key) {return key;})
		.catch(function(e) {
			// fallback for Safari 9
			return _generateKey(tag, opt2, usage2)
				.then(function(key) {
					// replace the signingKey with a re-generated `encryption' key
					var jwk = key.jwk;
					jwk.alg = undefined;	// workaround
					jwk.key_ops = usage;
					var s = JSON.stringify(jwk);
					var raw = new Uint8Array(s.length);
					for (var i = 0; i < s.length; i++)
						raw[i] = s.charCodeAt(i);
					return wc.importKey('jwk', raw, opt, false, usage)
						.then(function(privKey) {
							key.signingKey = privKey;
							return key;
						});
				});
		});
}

function fingerprint(key)
{
	return wc.digest('SHA-1', tbsform(key.pub))
		.then(function(h) {
			key.fingerprint = h;
			return key;
		});
}

function generatePGPKeys(userID)
{
	var uid = packetize(TAG_USER_ID, userID);
	var primkey, subkey, primsig, subsig;
	// primary key
	return generateKey(TAG_PUBLIC_KEY)
		.then(function(key) {return fingerprint(key);})
		.then(function(key) {return sign(primkey = key, SIGTYPE_GENERIC_CERT, [key.pub, uid]);})
	// sub key
		.then(function(sig) {primsig = sig; return generateKey(TAG_PUBLIC_SUB_KEY);})
		.then(function(key) {subkey = key; return sign(primkey, SIGTYPE_SUBKEY_BINDING, [primkey.pub, key.pub]);})
		.then(function(sig) {
			subsig = sig;
			var s = new Stream();
			s.putpkt(primkey.pub);
			s.putpkt(uid);
			s.putpkt(primsig);
			s.putpkt(subkey.pub);
			s.putpkt(subsig);
			var pubpart = s.flush();
			s = new Stream();
			s.putpkt(primkey.priv);
			s.putpkt(uid);
			s.putpkt(primsig);
			s.putpkt(subkey.priv);
			s.putpkt(subsig);
			var privpart = s.flush();
			return {pub: pubpart, priv: privpart, error: undefined};
		});
}

let wc = window.crypto.webkitSubtle || window.crypto.subtle;

let opt = {
	name: 'RSASSA-PKCS1-v1_5',
	modulusLength: 2048,
	publicExponent: new Uint8Array([3]),
	hash: {
		name: 'SHA-256' // not required for actual RSA keys, but for crypto api 'sign' and 'verify'
	}
};
let usage = ['sign', 'verify'];

const TAG_SIGNATURE = 2;
const TAG_PUBLIC_KEY = 6;
const TAG_PUBLIC_SUB_KEY = 14;
const TAG_USER_ID = 13;
const TAG_SECRET_KEY = 5;
const TAG_SECRET_SUB_KEY = 7;
const SIGTYPE_GENERIC_CERT = 0x10;
const SIGTYPE_SUBKEY_BINDING = 0x18;
const ALG_RSA = 1;
const ALG_AES128 = 7;
const ALG_SHA256 = 8;
const ALG_ZIP = 1;
const SS_CREATION_TIME = 2;
const SS_ISSUER = 16;
const SS_KEY_FLAGS = 27;
const SS_PREF_SYM = 11;
const SS_PREF_HASH = 21;
const SS_PREF_COMP = 22;
const SS_PRIMARY = 25;
const SS_FEATURES = 30;

class Stream {
	constructor() {
		this.buf = new Uint8Array(128);
		this.widx = 0;
	}
	morebuf(n) {
		if (n < 128) n = 128;
		let nbuf = new Uint8Array(this.buf.length + n);
		nbuf.set(this.buf);
		this.buf = nbuf;
	}
	nbits(x) {
		let n = 1, t;
		if ((t = x >>> 16) != 0) {
			x = t;
			n += 16;
		}
		if ((t = x >> 8) != 0) {
			x = t;
			n += 8;
		}
		if ((t = x >> 4) != 0) {
			x = t;
			n += 4;
		}
		if ((t = x >> 2) != 0) {
			x = t;
			n += 2;
		}
		if ((t = x >> 1) != 0) {
			x = t;
			n += 1;
		}
		return n;
	}
	putc(c) {
		if (this.widx >= this.buf.length)
			this.morebuf(1);
		this.buf[this.widx++] = c;
	}
	putn(n, nbytes) {
		while (--nbytes >= 0)
			this.putc((n >>> (nbytes * 8)) & 0xff);
	}
	puts(b) {
		let n = b.byteLength;
		if (n <= 0)
			return;
		if (this.widx + n > this.buf.length)
			this.morebuf(n);
		this.buf.set(new Uint8Array(b), this.widx);
		this.widx += n;
	}
	putmpi(b) {
		var a = new Uint8Array(b.byteLength + 2)
		a.set(new Uint8Array(b), 2)
		var bitsz = (b.byteLength - 1) * 8 + this.nbits(a[2])
		a[0] = (bitsz & 0xff00) >> 8;
		a[1] = bitsz & 0xff;
		this.puts(a.buffer);
	}
	put64(b64url) {
		let b64 = b64url.replace(/\-/g, '+').replace(/_/g, '/');
		let b = atob(b64);
		let a = new Uint8Array(b.length);
		for (let i = 0; i < b.length; i++)
			a[i] = b.charCodeAt(i);
		this.putmpi(a.buffer);
	}
	putpkt(pkt) {
		let tag = pkt.tag;
		let len = pkt.byteLength;
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
	}
	putss(type, val, n) {
		let len = n + 1;	// including the type octet
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
			for (let i = 0; i < n; i++)
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
	}
	flush() {
		return this.buf.slice(0, this.widx).buffer;
	}
}
		
function checksum_skey(mpis)
{
	let sum = 0;
	let a = new Uint8Array(mpis);
	for (let i = 0; i < a.length; i++)
		sum = (sum + a[i]) & 0xffff;
	return sum;
}

function packetize(tag, param)
{
	let p = new Stream();
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
			let pkt = ss.flush();
			p.puts(pkt);
			p.putn(checksum_skey(pkt), 2);
		}
		break;
	case TAG_USER_ID:
		let utf8 = unescape(encodeURIComponent(param));
		let userid = new Uint8Array(utf8.length);
		for (let i = 0; i < utf8.length; i++)
			userid[i] = utf8.charCodeAt(i);
		p.puts(userid.buffer);
		break;
	}
	let pkt = p.flush();
	pkt.tag = tag;
	return pkt;
}

function tbsform(pkt)
{
	let p = new Stream();
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
	let hs = new Stream();	// hashed sub packets
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
	let p = new Stream();
	p.putn(4, 1);	// version
	p.putn(stype, 1);	// signature type
	p.putn(ALG_RSA, 1);	// public key algorithm
	p.putn(ALG_SHA256, 1);	// hash algorithm
	// hashed subpackets
	p.putn(subpkt.byteLength, 2);
	p.puts(subpkt);
	let sigpkt = p.flush();
	// no unhashed subpackets
	p.putn(0, 2)
	// 5.2.3 "The concatenation of the data being signed and the signature data from the version number through the hashed subpacket data (inclusive) is hashed
	let ss = new Stream();
	data.forEach(d => ss.puts(tbsform(d)));
	ss.puts(sigpkt);
	// trailer
	ss.putc(4);
	ss.putc(0xff);
	ss.putn(sigpkt.byteLength, 4);
	tbs = ss.flush();
	return wc.digest('SHA-256', tbs)
		.then(h => {
			// hashed just for the first 16 bits digest, webcrypt sign() calculates hash on its own
			p.puts(h.slice(0, 2));
			return wc.sign({name: opt.name, hash: opt.hash.name}, key.keypair.privateKey, tbs);
		})
		.then(sig => {
			p.putmpi(sig);
			let pkt = p.flush();
			pkt.tag = TAG_SIGNATURE;
			return pkt;
		});
}

function processKey(tag, keypair)
{
	return wc.exportKey('jwk', keypair.privateKey)
		.then(jwk => {
			if (jwk instanceof ArrayBuffer)
				jwk = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(jwk)));
			let pub = packetize(tag, jwk);
			let priv = packetize(tag == TAG_PUBLIC_KEY ? TAG_SECRET_KEY : TAG_SECRET_SUB_KEY, jwk);
			return {tag, keypair, pub, priv}
		})
		.catch(e => {console.log("exportKey failed:", e); throw e});
}

function fingerprint(key)
{
	return wc.digest('SHA-1', tbsform(key.pub))
		.then(h => {
			key.fingerprint = h;
			return key;
		});
}

function generateKey(userID)
{
	let uid = packetize(TAG_USER_ID, userID);
	let primkey, subkey, primsig, subsig;
	// primary key
	return wc.generateKey(opt, true, usage)
		.then(keypair => processKey(TAG_PUBLIC_KEY, keypair))
		.then(key => fingerprint(key))
		.then(key => sign(primkey = key, SIGTYPE_GENERIC_CERT, [key.pub, uid]))
	// sub key
		.then(sig => (primsig = sig, wc.generateKey(opt, true, usage)))
		.then(keypair => processKey(TAG_PUBLIC_SUB_KEY, keypair))
		.then(key => (subkey = key, sign(primkey, SIGTYPE_SUBKEY_BINDING, [primkey.pub, key.pub])))
		.then(sig => {
			subsig = sig;
			let s = new Stream();
			s.putpkt(primkey.pub);
			s.putpkt(uid);
			s.putpkt(primsig);
			s.putpkt(subkey.pub);
			s.putpkt(subsig);
			let pubpart = s.flush();
			s = new Stream();
			s.putpkt(primkey.priv);
			s.putpkt(uid);
			s.putpkt(primsig);
			s.putpkt(subkey.priv);
			s.putpkt(subsig);
			let privpart = s.flush();
			return {pub: pubpart, priv: privpart};
		})
		.catch(e => console.log("generateKey failed:", e));
}

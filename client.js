const openpgp = window.openpgp;

const HKPSERVER = 'http://localhost:8000';

function b64decode(b64string)
{
	return Uint8Array.from(atob(b64string), c => c.charCodeAt(0));
}

function b64encode(buf)
{
	return btoa(String.fromCharCode.apply(null, buf));
}

function findQuorum(id)
{
	id = id.toLowerCase();
	return QUORUM_MEMBERS.find(e => e.id.toLowerCase() == id);
}

function quorum(cert)
{
	let random_choises = QUORUM_MEMBERS;	// for now
	let subjectKeyid = cert.primaryKey.keyid.toHex();

	// first verify the cert with quorum keys
	let u = cert.users[0];		// should have only one user (i.e., the key server ID)
	qs = [];
	u.otherCertifications.forEach(c => {
		let issuerid = c.issuerKeyId.toHex();
		let q = findQuorum(issuerid);
		if (q) {
			let key = openpgp.key.readArmored(q.key);
			if (c.verify(key.keys[0].primaryKey, {userid: u.userId, key: cert.primaryKey}))
				qs.push(q);
		}
	});
	// then check if the cert has been revoked
	return Promise.all(qs.map(qm => {
		let hkp = new openpgp.HKP(qm.uri);
		return hkp.lookup({query: subjectKeyid}).catch(e => {console.log("HKP.lookup", e); return undefined;});
	})).then(results => {
		let verified = results.filter(r => r && r.length).length
		return verified >= random_choises.length / 2;
	});
}

openpgp.HKP.prototype.getProof = function(h) {
	let uri = this._baseUrl + '/pks/lookup?op=x-get-proof&search=' + encodeURIComponent(b64encode(h));
	let fetch = this._fetch;
	return fetch(uri).then(response => {
		if (response.status == 200)
			return response.text();
	}).then(txt => JSON.parse(txt));
}

function hashChildren(left, right)
{
	let arr = new Uint8Array(1 + left.byteLength + right.byteLength);
	arr[0] = 1;	// node prefix
	arr.set(left, 1);
	arr.set(right, 1 + left.byteLength);
	return openpgp.crypto.hash.sha256(arr);
}

function hashLeaf(leaf)
{
	let arr = new Uint8Array(1 + leaf.byteLength);
	arr[0] = 0;	// leaf prefix
	arr.set(leaf, 1);
	return openpgp.crypto.hash.sha256(arr);
}

function checkPath(proof, h, results)
{
	let IS_RIGHT_CHILD = function(node) { return node & 1; }

	if (proof.leaf_index < 0 || !proof.audit_path)
		return false;
	let i = 0;
	for (let node = proof.leaf_index, last_node = proof.tree_size - 1; last_node != 0; node >>= 1, last_node >>= 1) {
		if (i >= proof.audit_path.length)
			return;
		if (IS_RIGHT_CHILD(node))
			h = hashChildren(b64decode(proof.audit_path[i++]), h);
		else if (node < last_node)
			h = hashChildren(h, b64decode(proof.audit_path[i++]));
	}
	if (proof.audit_path.length != i)
		return;
	// check to see if the calculated hash is the same as the root tree hash
	root = b64decode(proof.sha256_root_hash);
	if (root.length != h.length)
		return;
	for (i = 0; i < root.length; i++) {
		if (root[i] != h[i])
			return;
	}
	// @@ check the signature
	return results;
}

function checkProof(armoredkey, results)
{
	let hkp = new openpgp.HKP(HKPSERVER);
	if (results.length == 0)
		return results;
	else if (results.length == 1) {
		// no need to acquire the key again
		let decoded = openpgp.armor.decode(armoredkey);
		h = hashLeaf(decoded.data);
		return hkp.getProof(h).then(proof => checkPath(proof, h, results));
	}
	else {
		// need to get each key individually as we have registered them one by one
		return Promise.all(results.map(res => hkp.lookup({query: res.primaryKey.keyid.toHex()}).then(armoredkey => {
			let decoded = openpgp.armor.decode(armoredkey);
			h = hashLeaf(decoded.data);
			return hkp.getProof(h).then(proof => checkPath(proof, h, results));
		})));
	}
}

function checkKey(key)
{
	// check the self cert
	if (key.verifyPrimaryKey() != openpgp.enums.keyStatus.valid)
		console.log("no self cert");
	// find the userID packet (i.e., not a userAttribute)
	let user = key.users.find(u => u.userId.tag == 13);
	if (!user)
		throw new Error("no userID packet");
	// check if the cert is signed by the key server
	return Promise.all(user.otherCertifications.map(c => {
		let issuerid = c.issuerKeyId.toHex();
		hkp = new openpgp.HKP(HKPSERVER);
		return hkp.lookup({query: issuerid}).then(armoredkey => {
			if (!armoredkey) {
				console.log(issuerid + " not found");
				return false;
			}
			issuerkey = openpgp.key.readArmored(armoredkey);
			if (c.isExpired()) {
				console.log("expired");
				return false;
			}
			if (!c.verify(issuerkey.keys[0].primaryKey, {userid: user.userId, key: key.primaryKey})) {
				console.log("verification failed");
				return false;
			}
			return quorum(issuerkey.keys[0]);
		});
	})).then(results => results.every(r => r) ? key : undefined);
}

function lookup(id)
{
	let hkp = new openpgp.HKP(HKPSERVER);
	window._hkp = hkp;
	return hkp.lookup({query: id}).then(armoredkey => {
		if (!armoredkey)
			return [];
		let pubkey = openpgp.key.readArmored(armoredkey);
		return Promise.all(pubkey.keys.map(key => checkKey(key))).then(results => checkProof(armoredkey, results.filter(r => r))).then(results => results && results.filter(r => r));
	});
}

function generate(name, email)
{
	let genoptions = {
		userIds: [{ name: name, email: email }],	// multiple user IDs
		numBits: 2048,                                  // RSA key size
		//	passphrase: 'super long and hard to guess secret',         // protects the private key
		userAttribute: 'email address proof',
	};

	return openpgp.generateKey(genoptions).then(key => {
		var privkey = key.privateKeyArmored; // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
		var pubkey = key.publicKeyArmored;   // '-----BEGIN PGP PUBLIC KEY BLOCK ... '

		let storage = new openpgp.Keyring.localstore();
		let keys = openpgp.key.readArmored(privkey);
		storage.storePrivate(keys.keys);

		let hkp = new openpgp.HKP(HKPSERVER);
		return hkp.upload(pubkey);
	});
}

function encrypt(recipient, data)
{
	return lookup(recipient).then(keys => openpgp.encrypt({data, publicKeys: keys}));
}

function decrypt(data)
{
	let storage = new openpgp.Keyring.localstore();
	let privkey = storage.loadPrivate()
	return openpgp.decrypt({message: openpgp.message.readArmored(data), privateKey: privkey[0]});
}

//generate("Ryuji Ishiguro", "rishiguro@yahoo.com").then(result => console.log("generate", result)).catch(e => console.log("generate", e));
//lookup("ishiguro").then(results => console.log("lookup", results)).catch(e => console.log("lookup", e));
//encrypt("r2ishiguro", "this is a message").then(cipher => decrypt(cipher.data).then(plain => console.log(plain.data)));

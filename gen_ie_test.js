function b64(b) {
	let a = new Uint8Array(b);
	let str = [], s = "", j = 0;
	for (let i = 0; i < a.length; i++) {
		str[j++] = String.fromCharCode(a[i]);
		if ((j % 60) == 0) {
			console.log(btoa(str.join('')))
			j = 0;
			str = [];
		}
	}
	if (j != 0) {
		console.log(btoa(str.join('')))
	}
}

generateKey("foo <foo@example.com>")
	.then(function(keys) {
		console.log("pub:");
		b64(keys.pub);
		console.log("priv:");
		b64(keys.priv);
	})
	.catch(function(e) {console.log("generateKey: error:", e)})

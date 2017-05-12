/*
Copyright è¢Ì 2009, Jeff Mott. All rights reserved.
Copyright è¢Ì 2011, Paul Vorbach. All rights reserved.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.
* Neither the name Crypto-JS nor the names of its contributors may be used to
  endorse or promote products derived from this software without specific prior
  written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Convert a byte array to big-endian 32-bit words
function bytesToWords(bytes) {
	for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
		words[b >>> 5] |= bytes[i] << (24 - b % 32);
	return words;
}

// Convert big-endian 32-bit words to a byte array
function wordsToBytes(words) {
	for (var bytes = [], b = 0; b < words.length * 32; b += 8)
		bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
	return bytes;
}

function sha1(ab) {
	var message = new Uint8Array(ab);
        var m  = bytesToWords(message);
        l  = message.length * 8,
        w  = [],
        H0 =  1732584193,
        H1 = -271733879,
        H2 = -1732584194,
        H3 =  271733878,
        H4 = -1009589776;

	// Padding
	m[l >> 5] |= 0x80 << (24 - l % 32);
	m[((l + 64 >>> 9) << 4) + 15] = l;

	for (var i = 0; i < m.length; i += 16) {
		var a = H0,
		    b = H1,
		    c = H2,
		    d = H3,
		    e = H4;

		for (var j = 0; j < 80; j++) {

			if (j < 16)
				w[j] = m[i + j];
			else {
				var n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
				w[j] = (n << 1) | (n >>> 31);
			}

			var t = ((H0 << 5) | (H0 >>> 27)) + H4 + (w[j] >>> 0) + (
				j < 20 ? (H1 & H2 | ~H1 & H3) + 1518500249 :
					j < 40 ? (H1 ^ H2 ^ H3) + 1859775393 :
					j < 60 ? (H1 & H2 | H1 & H3 | H2 & H3) - 1894007588 :
					(H1 ^ H2 ^ H3) - 899497514);

			H4 = H3;
			H3 = H2;
			H2 = (H1 << 30) | (H1 >>> 2);
			H1 = H0;
			H0 = t;
		}

		H0 += a;
		H1 += b;
		H2 += c;
		H3 += d;
		H4 += e;
	}

	return (new Uint8Array(wordsToBytes([H0, H1, H2, H3, H4]))).buffer;
}

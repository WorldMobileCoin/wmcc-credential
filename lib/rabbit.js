'use strict';

const Rabbit = module.exports;

let x = [], c = [], b;

Rabbit.encrypt = function (message, password) {
	const m = Rabbit._UTF8.stringToBytes(message);
	const iv = Rabbit._utils.randomBytes(8);
	const k = password.constructor == String ? Rabbit._PBKDF2(password, iv, 32, { asBytes: true }) : password;

	Rabbit._internal(m, k, Rabbit._utils.bytesToWords(iv));

	return Rabbit._utils.bytesToHex(iv.concat(m));
};

Rabbit.decrypt = function (ciphertext, password) {
	const c = Rabbit._utils.hexToBytes(ciphertext), iv = c.splice(0, 8), k = password.constructor == String ?
			Rabbit._PBKDF2(password, iv, 32, { asBytes: true }) : password;

	Rabbit._internal(c, k, Rabbit._utils.bytesToWords(iv));

	return Rabbit._UTF8.bytesToString(c);
}

Rabbit._internal = function (m, k, iv) {
	Rabbit._keysetup(k);
	if (iv) Rabbit._ivsetup(iv);
  let s = [];
	for (let i = 0; i < m.length; i++) {
		if (i % 16 == 0) {
			Rabbit._nextstate();
			s[0] = x[0] ^ (x[5] >>> 16) ^ (x[3] << 16);
			s[1] = x[2] ^ (x[7] >>> 16) ^ (x[5] << 16);
			s[2] = x[4] ^ (x[1] >>> 16) ^ (x[7] << 16);
			s[3] = x[6] ^ (x[3] >>> 16) ^ (x[1] << 16);

			for (let j = 0; j < 4; j++) {
				s[j] = ((s[j] <<  8) | (s[j] >>> 24)) & 0x00FF00FF |
				       ((s[j] << 24) | (s[j] >>>  8)) & 0xFF00FF00;
			}
			for (let b = 120; b >= 0; b -= 8)
				s[b / 8] = (s[b >>> 5] >>> (24 - b % 32)) & 0xFF;
			}
		m[i] ^= s[i % 16];
	}
};

Rabbit._keysetup = function (k) {
	x[0] = k[0]; x[2] = k[1]; x[4] = k[2]; x[6] = k[3];
	x[1] = (k[3] << 16) | (k[2] >>> 16); x[3] = (k[0] << 16) | (k[3] >>> 16);
	x[5] = (k[1] << 16) | (k[0] >>> 16); x[7] = (k[2] << 16) | (k[1] >>> 16);

	c[0] = Rabbit._utils.rotl(k[2], 16); c[2] = Rabbit._utils.rotl(k[3], 16);
	c[4] = Rabbit._utils.rotl(k[0], 16); c[6] = Rabbit._utils.rotl(k[1], 16);
	c[1] = (k[0] & 0xFFFF0000) | (k[1] & 0xFFFF); c[3] = (k[1] & 0xFFFF0000) | (k[2] & 0xFFFF);
	c[5] = (k[2] & 0xFFFF0000) | (k[3] & 0xFFFF); c[7] = (k[3] & 0xFFFF0000) | (k[0] & 0xFFFF);

	b = 0;
	for (let i = 0; i < 4; i++) Rabbit._nextstate();
	for (let i = 0; i < 8; i++) c[i] ^= x[(i + 4) & 7];
}

Rabbit._ivsetup = function (iv) {
	const i0 = Rabbit._utils.endian(iv[0]), i2 = Rabbit._utils.endian(iv[1]),
		i1 = (i0 >>> 16) | (i2 & 0xFFFF0000), i3 = (i2 <<  16) | (i0 & 0x0000FFFF);

	c[0] ^= i0; c[1] ^= i1; c[2] ^= i2; c[3] ^= i3; c[4] ^= i0; c[5] ^= i1; c[6] ^= i2; c[7] ^= i3;

	for (let i = 0; i < 4; i++) Rabbit._nextstate();
}

Rabbit._nextstate = function () {
  let c_old = [];
	for (let i = 0; i < 8; i++) c_old[i] = c[i];

	c[0] = (c[0] + 0x4D34D34D + b) >>> 0;
	c[1] = (c[1] + 0xD34D34D3 + ((c[0] >>> 0) < (c_old[0] >>> 0) ? 1 : 0)) >>> 0;
	c[2] = (c[2] + 0x34D34D34 + ((c[1] >>> 0) < (c_old[1] >>> 0) ? 1 : 0)) >>> 0;
	c[3] = (c[3] + 0x4D34D34D + ((c[2] >>> 0) < (c_old[2] >>> 0) ? 1 : 0)) >>> 0;
	c[4] = (c[4] + 0xD34D34D3 + ((c[3] >>> 0) < (c_old[3] >>> 0) ? 1 : 0)) >>> 0;
	c[5] = (c[5] + 0x34D34D34 + ((c[4] >>> 0) < (c_old[4] >>> 0) ? 1 : 0)) >>> 0;
	c[6] = (c[6] + 0x4D34D34D + ((c[5] >>> 0) < (c_old[5] >>> 0) ? 1 : 0)) >>> 0;
	c[7] = (c[7] + 0xD34D34D3 + ((c[6] >>> 0) < (c_old[6] >>> 0) ? 1 : 0)) >>> 0;
	b = (c[7] >>> 0) < (c_old[7] >>> 0) ? 1 : 0;

	let g = [];
  for (let i = 0; i < 8; i++) {
		const gx = (x[i] + c[i]) >>> 0;
		const ga = gx & 0xFFFF,
		    gb = gx >>> 16;

		const gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb,
		    gl = (((gx & 0xFFFF0000) * gx) >>> 0) + (((gx & 0x0000FFFF) * gx) >>> 0) >>> 0;

		g[i] = gh ^ gl;
	}

	x[0] = g[0] + ((g[7] << 16) | (g[7] >>> 16)) + ((g[6] << 16) | (g[6] >>> 16));
	x[1] = g[1] + ((g[0] <<  8) | (g[0] >>> 24)) + g[7];
	x[2] = g[2] + ((g[1] << 16) | (g[1] >>> 16)) + ((g[0] << 16) | (g[0] >>> 16));
	x[3] = g[3] + ((g[2] <<  8) | (g[2] >>> 24)) + g[1];
	x[4] = g[4] + ((g[3] << 16) | (g[3] >>> 16)) + ((g[2] << 16) | (g[2] >>> 16));
	x[5] = g[5] + ((g[4] <<  8) | (g[4] >>> 24)) + g[3];
	x[6] = g[6] + ((g[5] << 16) | (g[5] >>> 16)) + ((g[4] << 16) | (g[4] >>> 16));
	x[7] = g[7] + ((g[6] <<  8) | (g[6] >>> 24)) + g[5];
}

Rabbit._utils = {
	randomBytes: function (n) {
    let bytes = [];
		for (n; n > 0; n--) bytes.push(Math.floor(Math.random() * 256));
		return bytes;
	},
	randomHex: function (n) {
		const hex = Rabbit._utils.bytesToHex(Rabbit._utils.randomBytes(n));
		return hex;
	},
	wordsToBytes: function (words) {
    let bytes = [];
		for (let b = 0; b < words.length * 32; b += 8) bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
		return bytes;
	},
	bytesToWords: function (bytes) {
    let words = [];
		for (let i = 0, b = 0; i < bytes.length; i++, b += 8)
			words[b >>> 5] |= bytes[i] << (24 - b % 32);
		return words;
	},
	bytesToHex: function (bytes) {
    let hex = [];
		for (let i = 0; i < bytes.length; i++) {
			hex.push((bytes[i] >>> 4).toString(16));
			hex.push((bytes[i] & 0xF).toString(16));
		}
		return hex.join("");
	},
	hexToBytes: function (hex) {
    let bytes = [];
		for (let c = 0; c < hex.length; c += 2)
			bytes.push(parseInt(hex.substr(c, 2), 16));
		return bytes;
	},
	wordsToHex: function(words){
		const hex = new Buffer(Buffer.from(words).toString('hex'));
		return hex;
	},
	rotl: function (n, b) {
		return (n << b) | (n >>> (32 - b));
	},
	endian: function (n) {
		if (n.constructor == Number) {
			return Rabbit._utils.rotl(n,  8) & 0x00FF00FF | Rabbit._utils.rotl(n, 24) & 0xFF00FF00;
		}
		for (let i = 0; i < n.length; i++) n[i] = Rabbit._utils.endian(n[i]);
		return n;
	}
};

Rabbit._UTF8 = {
	stringToBytes: function (str) {
		return Rabbit._Binary.stringToBytes(unescape(encodeURIComponent(str)));
	},
	bytesToString: function (bytes) {
		try { return decodeURIComponent(escape(Rabbit._Binary.bytesToString(bytes))); } 
		catch (ex) { throw new Error("ERROR DECODING URI: " + ex.message); }
	}
};

Rabbit._Binary = {
	stringToBytes: function (str) {
    let bytes = [];
		for (let i = 0; i < str.length; i++) bytes.push(str.charCodeAt(i) & 0xFF);
		return bytes;
	},
	bytesToString: function (bytes) {
    let str = [];
		for (let i = 0; i < bytes.length; i++) str.push(String.fromCharCode(bytes[i]));
		return str.join("");
	}
};

Rabbit._PBKDF2 = function (password, salt, keylen, options) {
	if (password.constructor == String) password = Rabbit._UTF8.stringToBytes(password);
	if (salt.constructor == String) salt = Rabbit._UTF8.stringToBytes(salt);

	const hasher = options && options.hasher || Rabbit._SHA1, iterations = options && options.iterations || 1;

	function PRF(password, salt) {
		return Rabbit._HMAC(hasher, salt, password, { asBytes: true });
	}

	let derivedKeyBytes = [], blockindex = 1;
	while (derivedKeyBytes.length < keylen) {
		let block = PRF(password, salt.concat(Rabbit._utils.wordsToBytes([blockindex])));
    let u = block;
		for (let i = 1; i < iterations; i++) {
			u = PRF(password, u);
			for (let j = 0; j < block.length; j++) block[j] ^= u[j];
		}
		derivedKeyBytes = derivedKeyBytes.concat(block);
		blockindex++;
	}

	derivedKeyBytes.length = keylen;

	return options && options.asBytes ? derivedKeyBytes :
		options && options.asString ? Rabbit._Binary.bytesToString(derivedKeyBytes) :
		Rabbit._utils.bytesToHex(derivedKeyBytes);
};

Rabbit._SHA1 = function (message, options) {
	const digestbytes = Rabbit._utils.wordsToBytes(Rabbit._SHA1._internal(message));
	return options && options.asBytes ? digestbytes :
	       options && options.asString ? Rabbit._Binary.bytesToString(digestbytes) :
	       Rabbit._utils.bytesToHex(digestbytes);
};

Rabbit._SHA1._internal = function (message) {
	if (message.constructor == String) message = Rabbit._UTF8.stringToBytes(message);

	let m = Rabbit._utils.bytesToWords(message),
		l = message.length * 8,
		w =  [],
		H0 =  1732584193,
		H1 = -271733879,
		H2 = -1732584194,
		H3 =  271733878,
		H4 = -1009589776;

	m[l >> 5] |= 0x80 << (24 - l % 32);
	m[((l + 64 >>> 9) << 4) + 15] = l;

	for (let i = 0; i < m.length; i += 16) {
		let a = H0, b = H1, c = H2, d = H3, e = H4;

		for (let j = 0; j < 80; j++) {
			if (j < 16) w[j] = m[i + j];
			else {
				let n = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16];
				w[j] = (n << 1) | (n >>> 31);
			}

			const t = ((H0 << 5) | (H0 >>> 27)) + H4 + (w[j] >>> 0) + (
				j < 20 ? (H1 & H2 | ~H1 & H3) + 1518500249 :
				j < 40 ? (H1 ^ H2 ^ H3) + 1859775393 :
				j < 60 ? (H1 & H2 | H1 & H3 | H2 & H3) - 1894007588 :
				(H1 ^ H2 ^ H3) - 899497514);

			H4 =  H3; H3 =  H2; H2 = (H1 << 30) | (H1 >>> 2); H1 = H0; H0 = t;
		}

		H0 += a; H1 += b; H2 += c; H3 += d; H4 += e;
	}

	return [H0, H1, H2, H3, H4];
};

Rabbit._HMAC = function (hasher, message, key, options) {

	if (message.constructor == String) message = Rabbit._UTF8.stringToBytes(message);
	if (key.constructor == String) key = Rabbit._UTF8.stringToBytes(key);

	if (key.length > hasher._blocksize * 4) key = hasher(key, { asBytes: true });

	let okey = key.slice(0);
	let ikey = key.slice(0);
	for (let i = 0; i < hasher._blocksize * 4; i++) {
		okey[i] ^= 0x5C;
		ikey[i] ^= 0x36;
	}

	const hmacbytes = hasher(okey.concat(hasher(ikey.concat(message), { asBytes: true })), { asBytes: true });

	return options && options.asBytes ? hmacbytes :
		options && options.asString ? Rabbit._Binary.bytesToString(hmacbytes) :
		Rabbit._utils.bytesToHex(hmacbytes);
};

module.exports = Rabbit;
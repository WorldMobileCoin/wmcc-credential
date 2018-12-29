/*!
 * Copyright (c) 2018, Park Alter (pseudonym)
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php
 *
 * https://github.com/worldmobilecoin/wmcc-desktop
 */

'use strict';

const Assert = require('assert');
const {crypto, utils} = require('wmcc-core');
//--
const {
  cleanse,
  digest,
  pbkdf2,
  scrypt
} = crypto;
const {
  util//,
  //Lock
} = utils;

class HSM {
  constructor(options) {
    this.alg = HSM.alg.PBKDF2;
    this.hash = HSM.hashByVal[1];
    this.iter = 10000;
    this.salt = Buffer.alloc(0);
    this.r = 0;
    this.p = 0;
    this.length = 32;

    if (options)
      this._fromOptions(options);
  }

  encrypt(wid, salt, secret) {
    return new Promise(async (resolve) => {
      if (!wid && !salt && !secret)
        throw new Error('WalletID, DOB and Secret are required.');

      Assert(secret instanceof Array);
      for(let i=0; i<secret.length; i++)
        Assert(secret[i] instanceof Object);

      let ret;
      this.hashlock = await this.derive(wid, salt);
      resolve(this.secret(secret));
    });
  }

  decrypt(wid, salt, lock) {
    return new Promise(async (resolve) => {
      if (!wid && !salt && !lock)
        throw new Error('WalletID, DOB and Lock are required.');

      if (util.isHex(lock)){
        const reg = new RegExp(`.{1,${this.length*2+2}}`, "g");
        const hex = lock.match(reg);
        lock = [];
        for(let i=0; i<hex.length; i++)
          lock[i] = Buffer.from(hex[i], 'hex');
      } else if (Buffer.isBuffer(lock)) {
        const l = lock;
        const len = this.length + 1;
        lock = [];
        for(let i=0; i<l.length/len; i++)
          lock[i] = l.slice(i*len,i*len+len);
      }
      // check length
      for(let i=0; i<lock.length; i++)
        Assert(lock[i].length === this.length + 1);

      Assert(lock instanceof Array);

      this.hashlock = await this.derive(wid, salt);
      this.answers = Buffer.alloc(0);
      this.locks = lock.slice(0);
      this.salt = Buffer.from(salt, 'utf8');
      resolve(await this.question());
    });
  }

  destroy() {
    if (this.hashlock) {
      cleanse(this.hashlock);
      this.hashlock = null;
    }

    if (this.answers) {
      this.answers = null;
    }

    if (this.locks) {
      cleanse(this.locks);
      this.locks = null;
    }
  }

  secret(secret) {
    if (!this.hashlock) return null;
    let ret = {};
    let a = Buffer.alloc(0);
    let ha = Buffer.alloc(0);
    ret.locks = [];
    for(let i=0; i<secret.length; i++){
      ret.locks[i] = this.lock(Buffer.from(secret[i].question));
      ha = digest.sha256(Buffer.from(secret[i].answer));
      a = digest.sha256(Buffer.concat([a, ha]));
    }
    ret.passphrase = this.passphrase(a);
    return ret;
  }

  lock(question) {
    if (!this.hashlock) return null;
    let buf;
    buf = Buffer.alloc(randomRange(question.length, this.length), 0);
    buf.write(question.toString().replace(/\0/g, ''), 0);
    const p = this.hashlock.toString('ascii');
    const q = Buffer.from(buf).toString('ascii');
    const l = Buffer.from(Array.prototype.map.call(p,function(c, i) {
      return c.charCodeAt(0) ^ bufferAt(q, i);
    }));
    return Buffer.concat([Buffer.from([buf.length]), l]);
  }

  passphrase(answer) {
    Assert(Buffer.isBuffer(answer));
    if (!this.hashlock) return null;
    const l = digest.sha256(this.hashlock).toString('ascii');
    const a = digest.sha256(answer).toString('ascii');
    const k = Buffer.from(Array.prototype.map.call(l,function(c, i) {
      return c.charCodeAt(0) ^ bufferAt(a, i);
    }));
    return k;
  }

  question() {
    if (!this.hashlock) return null;
    let ret = {};
    if (this.locks.length){
      const p = this.hashlock.toString('ascii');
      const l = this.locks[0].slice(1, this.locks[0][0]+ 1);
      this.locks.shift();

      ret.question = Buffer.from(Array.prototype.map.call(l,function(c, i) {
        return String.fromCharCode( c ^ bufferAt(p, i) );
      }).join("").replace(/\0/g, ''));
    } else {
      ret.passphrase = this.passphrase(this.answers);
    }
    return ret;
  }

  setAnswer(answer) {
    const ha = digest.sha256(Buffer.from(answer));
    const a = (this.answers) ? Buffer.concat([this.answers, ha]) : ha;
    this.answers = digest.sha256(a);
    return this.question();
  }

  async derive(wid, salt) {
    const i = this.iter;
    const h = this.hash;
    const r = this.r;
    const p = this.p;

    if (typeof wid === 'string'){
      let buf = Buffer.alloc(this.length, 0);
      buf.write(wid.replace(/\0/g, ''), 0);
    }

    if (!Buffer.isBuffer(salt))
      salt = Buffer.from(salt, 'utf8');

    switch (this.alg) {
       case HSM.alg.PBKDF2:
        return await pbkdf2.deriveAsync(wid, salt, i, this.length, h);
      case HSM.alg.SCRYPT:
        return await scrypt.deriveAsync(wid, salt, i, r, p, this.length);
      default:
        throw new Error(`Unknown algorithm: ${this.alg}.`);
    }
  }

  static toObject(hsm) {
    let lock;
    if (Array.isArray(hsm.locks)) {
      lock = util.concatArrBuf(hsm.locks);
    } else if (typeof hsm.locks === 'string') {
      Assert(util.isHex(hsm.locks));
      lock = Buffer.from(hsm.locks, 'hex');
    } else {
      lock = hsm.locks;
    }

    Assert(Buffer.isBuffer(lock));
    Assert(Buffer.isBuffer(hsm.passphrase));

    return {
      lock: lock,
      chksum: hsm.passphrase.slice(0, 4)
    };
  }

  _fromOptions(options){
    Assert(typeof options === 'object');

    if (options.alg != null) {
      if (typeof options.alg === 'string') {
        this.alg = HSM.alg[options.alg.toUpperCase()];
        Assert(this.alg != null, 'Unknown algorithm.');
      } else {
        Assert(typeof options.alg === 'number');
        Assert(HSM.algByVal[options.alg]);
        this.alg = options.alg;
      }
    }

    if (options.hash != null) {
      if (typeof options.hash === 'string') {
        Assert(HSM.hash[options.hash.toUpperCase()] != null, 'Unknown hash.');
        this.hash = HSM.hashByVal[HSM.hash[options.hash.toUpperCase()]];
      } else {
        Assert(typeof options.hash === 'number');
        Assert(HSM.hashByVal[options.hash]);
        this.hash = HSM.hashByVal[options.hash];
      }
    }

    if (options.iter != null) {
      Assert(util.isU32(options.iter));
      this.iter = options.iter;
    }

    if (options.r != null) {
      Assert(util.isU32(options.r));
      this.r = options.r;
    }

    if (options.p != null) {
      Assert(util.isU32(options.p));
      this.p = options.p;
    }

    if (options.length != null) {
      Assert(util.isU32(options.length));
      this.length = options.length;
    }
  }
}

/**
 * Constant
 */
HSM.alg = {
  PBKDF2: 0,
  SCRYPT: 1
};

HSM.algByVal = {
  0: 'PBKDF2',
  1: 'SCRYPT'
};

HSM.hash = {
  SHA256: 0,
  SHA512: 1
};

HSM.hashByVal = {
  0: 'SHA256',
  1: 'SHA512'
};

/*
 * Helper
 */
function randomRange(min, max) {
  return Math.floor(Math.random()*(max-min+1)+min);
}

function bufferAt(key, i){
  return key.charCodeAt( Math.floor(i % key.length) );
}

/*
 * Expose
 */
module.exports = HSM;
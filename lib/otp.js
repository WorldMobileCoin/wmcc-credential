/*!
 * Copyright (c) 2018, Park Alter (pseudonym)
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php
 *
 * https://github.com/worldmobilecoin/wmcc-desktop
 */

'use strict';

const Assert = require('assert');
const Crypto = require("crypto");
//--
const {crypto} = require('wmcc-core');
//--
const Rabbit = require('./rabbit');
//--
const {
  digest
} = crypto;

/**
 * @module wmcc-credential.OTP
 */
class OTP {
  constructor(bool) {
    this.enable = bool;
    this.code = null;
    this.key = null;
    this.retry = 0;
    this.maxtry = 5;
  }

  encode(passphrase) {
    Assert(passphrase, 'Passphrase required.');
    const otp = randomRange(1000, 9999);
    this.code = Crypto.randomBytes(16).toString('hex');
    const code = this._generateCode(otp);
    this.key = Rabbit.encrypt(passphrase, code);
    return otp;
  }

  decode(otp, renew) {
    Assert(this.code, 'OTP must be instantiate first');
    const code = this._generateCode(otp);

    let passphrase;
    try {
      passphrase = Buffer.from(Rabbit.decrypt(this.key, code), 'ascii');
    } catch (e){
      this.retry++;
      if (this.retry > this.maxtry-1)
        setTimeout(() => {location.reload();}, 2000 );
      return false;
    }
    this.retry = 0;

    if (renew) {
      const otp = this.encode(passphrase);
      return {passphrase: passphrase, otp: otp}
    }
    return passphrase;
  }

  isEnabled() {
    return this.enable;
  }

  _generateCode(otp) {
    Assert(otp, 'OTP required.');
    let code;
    for (let i=0; i<otp; i++) {
      if (i === 0) code = this.code;
      code = digest.sha256(Buffer.from(code)).toString('ascii');
    }
    return code;
  }
}

/**
 * Helper
 */
function randomRange(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * Expose
 */
module.exports = OTP;
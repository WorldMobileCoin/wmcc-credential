/*!
 * Copyright (c) 2018, Park Alter (pseudonym)
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php
 *
 * https://github.com/worldmobilecoin/wmcc-desktop
 */

'use strict';

const Crypto = require('crypto');
const Assert = require('assert');
//--
const Logger = require('wmcc-logger');
const Core = require('wmcc-core');
//--
const HSM = require('./hsm');
const OTP = require('./otp');
//--
const {
  utils,
  protocol
} = Core;
const {
  fs
} = utils;
const {
  Network
} = protocol;

/**
 * @module wmcc-credential.Auth
 */
class Auth {
  constructor(options) {
    this.options = new AuthOptions(options);

    this.hsm = new HSM({
      alg: this.options.alg,
      hash: this.options.hash,
      iter: this.options.iter,
      r: this.options.r,
      p: this.options.p,
      length: this.options.length
    });

    this.otp = new OTP(this.options.otp);

    this.walletdb = this.options.walletdb;
    this.chain = this.options.chain;
    this.network = this.options.network;
    this.logger = this.options.logger.context('authentication');

    this.maxLock = this.options.maxLock;
    this.logged = false;

    this._opened = false;
    this._walletdb = new Map();
    this._wallets = [];
  }

  hasWallet(name) {
    return this._wallets.includes(name);
  }

  addWallet(name) {
    this._wallets = this._wallets.filter(val => val !== name).concat([name]).sort();
  }

  walletCount() {
    return this._wallets.length;
  }


  async create(id, salt, secret) {
    const hsm = await this.hsm.encrypt(id, salt, secret);
    const suffix = this.toSuffix(id);

    const walletdb = await this._create(suffix);
    walletdb.skipSync();
    await walletdb.open();
    await walletdb.set({id: id, hsm: hsm});

    await this.hsm.destroy();
    await walletdb.close();
  }

  async load(suffix) {
    const walletdb = Core.walletdb(this.walletdb.options);
    this._walletdb.set(suffix, walletdb);

    walletdb.suffix(suffix);
    await this._ensure(walletdb.db.db.location);
    await this.open(suffix);

    return walletdb;
  }

  async _create(suffix) {
    const walletdb = Core.walletdb(this.walletdb.options);

    if (!this.chain.loaded)
      await this.chain.open();

    walletdb.suffix(suffix);
    await this._ensure(walletdb.db.db.location);

    return walletdb;
  }

  async open(suffix) {
    if (!this.chain.loaded)
      await this.chain.open();
    // dont bind to emitter
    const walletdb = this._walletdb.get(suffix);
    const bound = walletdb.bound;
    if (this._opened)
      walletdb.bound = true;

    await walletdb.db.open();
    walletdb.bound = bound;

    this._opened = true;
  }

  async close(suffix, closeChain) {
    const walletdb = this._walletdb.get(suffix);

    if (!walletdb)
      return;

    await walletdb.db.close();
    this._walletdb.delete(suffix);

    if (closeChain)
      await this.chain.close();

    this._opened = false;
  }

  toSuffix(wid) {
    const cip = Crypto.createCipher('aes128', 'wmcc-wallet');
    const cto = cip.update(wid,'utf8','hex');
    return `${cto}${cip.final('hex')}`;
  }

  fromSuffix(suffix) {
    const dcip = Crypto.createDecipher('aes128', 'wmcc-wallet');
    const sfx = dcip.update(suffix,'hex','utf8');
    return `${sfx}${dcip.final('utf8')}`;
  }

  getOTP(passphrase) {
    return this.otp.encode(passphrase);
  }

  getPassphrase(otp, renew) {
    return this.otp.decode(otp, renew);
  }

  isOtpEnabled() {
    return this.otp.isEnabled();
  }

  getMaxLock() {
    // todo: temp, set this to auth options
    return this.maxLock;
  }

  /**
   * return {Promise}
   */
  _ensure(path) {
    if (fs.unsupported)
      return Promise.resolve();

    return fs.mkdirp(path);
  }
}

class AuthOptions {
  constructor(options) {
    this.network = Network.primary;
    this.logger = Logger.global;
    this.otp = true;
    this.maxLock = 10;

    this.fromOptions(options);
  }

  fromOptions(options) {
    Assert(typeof options.walletdb === 'object');
    Assert(typeof options.chain === 'object');

    this.walletdb = options.walletdb;
    this.chain = options.chain;

    if (options.network != null)
      this.network = Network.get(options.network);

    if (options.logger != null) {
      Assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.otp != null) {
      Assert(typeof options.otp === 'boolean');
      this.otp = options.otp;
    }

    if (options.maxLock != null) {
      Assert(typeof options.maxLock === 'number');
      this.maxLock = options.maxLock;
    }

    if (options.alg != null) {
      Assert(typeof options.alg === 'string' || typeof options.alg === 'number');
      this.alg = options.alg;
    }

    if (options.hash != null) {
      Assert(typeof options.hash === 'string' || typeof options.hash === 'number');
      this.hash = options.hash;
    }

    if (options.iter != null) {
      Assert(typeof options.iter === 'number');
      this.iter = options.iter;
    }

    if (options.r != null) {
      Assert(typeof options.r === 'number');
      this.r = options.r;
    }

    if (options.p != null) {
      Assert(typeof options.p === 'number');
      this.p = options.p;
    }

    if (options.length != null) {
      Assert(typeof options.length === 'number');
      this.length = options.length;
    }

    return this;
  }
}

module.exports = Auth;
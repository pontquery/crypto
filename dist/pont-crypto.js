/*!
  * @pont/crypto v0.0.1
  * (c) 2020 Gabin Desserprit
  * @license MIT
  */
'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var crypto = require('@trust/webcrypto');
var util = require('util');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var util__default = /*#__PURE__*/_interopDefaultLegacy(util);

function decode(buffer) {
  return new util__default['default'].TextDecoder().decode(buffer)
}

function encode(data) {
  if (data instanceof Uint8Array) {
    return data
  } else if (typeof data === 'string') {
    return new util__default['default'].TextEncoder().encode(data)
  } else if (typeof data === 'object') {
    return new util__default['default'].TextEncoder().encode(JSON.stringify(data))
  }
}

function fromHash(hash) {
  return Buffer.from(hash.toString('hex'), 'hex')
}

function toHash(buffer) {
  return buffer.toString('hex').toString('base64')
}

async function generateCounter(counterLength = 16) {
  return crypto__default['default'].getRandomValues(new Uint8Array(counterLength))
}

const AES = {
  async generateKey() {
    return crypto__default['default'].subtle.generateKey({ name: 'AES-CTR', length: 128 }, true, ['encrypt', 'decrypt'])
  },

  async exportKey(key) {
    return crypto__default['default'].subtle.exportKey('raw', key).then(toHash)
  },

  async importKey(hashedKey) {
    let bufferKey = hashedKey;
    if (!Buffer.isBuffer(bufferKey)) bufferKey = fromHash(bufferKey);
    return crypto__default['default'].subtle.importKey('raw', bufferKey, { name: 'AES-CTR' }, true, ['encrypt', 'decrypt'])
  },

  encryptedToHashed(encrypted, counter) {
    return toHash(Buffer.concat([counter, new Uint8Array(encrypted)]))
  },

  hashedToEncryptedAndCounter(hashed, counterLength = 16) {
    const buffer = Buffer.from(hashed.toString('hex'), 'hex');
    const counter = buffer.slice(0, counterLength);
    const encrypted = buffer.slice(counterLength);
    return { counter, encrypted }
  },

  async encrypt(key, data, counter) {
    if (!counter) counter = await generateCounter();
    const encrypted = await crypto__default['default'].subtle.encrypt({ name: 'AES-CTR', counter, length: 128 }, key, encode(data));
    const hashed = this.encryptedToHashed(encrypted, counter);
    return hashed
  },

  async decrypt(key, encryptedHash) {
    const { counter, encrypted } = this.hashedToEncryptedAndCounter(encryptedHash);
    const decrypted = await crypto__default['default'].subtle.decrypt({ name: 'AES-CTR', counter, length: 128 }, key, encrypted);
    const decoded = decode(decrypted);
    return decoded
  },
};

const RSA = {
  async generateKeyPair() {
    return crypto__default['default'].subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: 'SHA-1' },
      },
      true,
      ['encrypt', 'decrypt']
    )
  },

  async exportKey(key) {
    return crypto__default['default'].subtle.exportKey('jwk', key).then((keyObj) => toHash(Buffer.from(JSON.stringify(keyObj))))
  },

  async exportKeyPair(keyPair) {
    return {
      publicKey: await this.exportKey(keyPair.publicKey),
      privateKey: await this.exportKey(keyPair.privateKey),
    }
  },

  async importKey(hashedKey, keyUsages = ['encrypt']) {
    const keyObj = JSON.parse(decode(fromHash(hashedKey)));
    return crypto__default['default'].subtle.importKey('jwk', keyObj, { name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, true, keyUsages)
  },

  async importPublicKey(hashedKey) {
    return this.importKey(hashedKey, ['encrypt'])
  },

  async importPrivateKey(hashedKey) {
    return this.importKey(hashedKey, ['decrypt'])
  },

  encryptedToHashed(encrypted) {
    return toHash(Buffer.from(encrypted, 'hex'))
  },

  hashedToEncrypted(hashed) {
    return Buffer.from(hashed.toString('hex'), 'hex')
  },

  async encrypt(publicKey, data) {
    const encrypted = await crypto__default['default'].subtle.encrypt({ name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, publicKey, encode(data));
    const hashed = this.encryptedToHashed(encrypted);
    return hashed
  },

  async decrypt(privateKey, encryptedHash) {
    const encrypted = this.hashedToEncrypted(encryptedHash);
    const decrypted = await crypto__default['default'].subtle.decrypt({ name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, privateKey, encrypted);
    const decoded = decode(decrypted);
    return decoded
  },
};

// Client
class CryptoClient {
  hashedKey = null
  hashedPublicKey = null
  constructor(hashedKey) {
    if (hashedKey) {
      this.hashedKey = hashedKey;
    }
  }

  async init() {
    if (!this.hashedKey) {
      const key = await AES.generateKey();
      this.hashedKey = await AES.exportKey(key);
    }
  }

  /**
   * Save the public key provided by the server
   * @param {*} hashedPublicKey
   */
  setPublicKey(hashedPublicKey) {
    this.hashedPublicKey = hashedPublicKey;
  }

  /**
   * Used to send the AES key to the server securely using the provided RSA PublicKey
   * @param {*} hashedPublicKey
   */
  async encryptKey() {
    const publicKey = await RSA.importPublicKey(this.hashedPublicKey);
    return RSA.encrypt(publicKey, this.hashedKey)
  }

  /**
   * Used to encrypt the body with the AES key to let the server securely read it
   * @param {*} hashedPublicKey
   * @param {*} body
   */
  async encryptBody(body) {
    const publicKey = await RSA.importPublicKey(this.hashedPublicKey);
    return RSA.encrypt(publicKey, body)
  }

  /**
   * Used to decrypt the body with the AES key (safely encrypted by the server)
   * @param {*} encryptedBody
   */
  async decrypteBody(encryptedBody) {
    const key = await AES.importKey(this.hashedKey);
    return AES.decrypt(key, encryptedBody)
  }
}

class CryptoServer {
  hashedKey = null
  hashedPublicKey = null
  hashedPrivateKey = null
  constructor({ hashedPublicKey, hashedPrivateKey, hashedKey } = {}) {
    if (hashedPublicKey) this.hashedPublicKey = hashedPublicKey;
    if (hashedPrivateKey) this.hashedPrivateKey = hashedPrivateKey;
    if (hashedKey) this.hashedKey = hashedKey;
  }

  async init() {
    if (!this.hashedPublicKey || !this.hashedPrivateKey) {
      const keyPair = await RSA.generateKeyPair();
      const { publicKey, privateKey } = await RSA.exportKeyPair(keyPair);
      this.hashedPublicKey = publicKey;
      this.hashedPrivateKey = privateKey;
    }
  }

  /**
   * Save the key provided by the client
   * @param {*} encryptedHashedKey
   */
  async setKey(encryptedHashedKey) {
    const privateKey = await RSA.importPrivateKey(this.hashedPrivateKey);
    const decryptedKey = await RSA.decrypt(privateKey, encryptedHashedKey);
    this.hashedKey = decryptedKey;
  }

  /**
   * Decrypt body encrypted by the client with the public key
   * @param {*} encryptedBody 
   */
  async decryptBody(encryptedBody) {
    const privateKey = await RSA.importPrivateKey(this.hashedPrivateKey);
    return RSA.decrypt(privateKey, encryptedBody)
  }

  /**
   * Encrypt the body to be sent to the client with the client provided key
   * @param {*} body 
   */
  async encryptBody(body) {
    const key = await AES.importKey(this.hashedKey);
    return AES.encrypt(key, body)
  }

  /**
   * The hashedUserKey would be provided (after a self decryption from a top level key)
   * @param {*} hashedUserKey
   * @param {*} data
   */
  async encryptUserData(hashedUserKey, data) {
    const userKey = await AES.importKey(hashedUserKey);
    return AES.encrypt(userKey, data)
  }

  /**
   * The hashedUserKey would be provided (after a self decryption from a top level key)
   * @param {*} hashedUserKey
   * @param {*} encryptedData
   */
  async decryptUserData(hashedUserKey, encryptedData) {
    const userKey = await AES.importKey(hashedUserKey);
    return AES.decrypt(userKey, encryptedData)
  }
}

exports.AES = AES;
exports.CryptoClient = CryptoClient;
exports.CryptoServer = CryptoServer;
exports.RSA = RSA;

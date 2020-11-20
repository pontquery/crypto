import crypto from '@trust/webcrypto'
import util from 'util'

function decode(buffer) {
  return new util.TextDecoder().decode(buffer)
}

function encode(data) {
  if (data instanceof Uint8Array) {
    return data
  } else if (typeof data === 'string') {
    return new util.TextEncoder().encode(data)
  } else if (typeof data === 'object') {
    return new util.TextEncoder().encode(JSON.stringify(data))
  }
}

function fromHash(hash) {
  return Buffer.from(hash.toString('hex'), 'hex')
}

function toHash(buffer) {
  return buffer.toString('hex').toString('base64')
}

async function generateCounter(counterLength = 16) {
  return crypto.getRandomValues(new Uint8Array(counterLength))
}

export const AES = {
  async generateKey() {
    return crypto.subtle.generateKey({ name: 'AES-CTR', length: 128 }, true, ['encrypt', 'decrypt'])
  },

  async exportKey(key) {
    return crypto.subtle.exportKey('raw', key).then(toHash)
  },

  async importKey(hashedKey) {
    let bufferKey = hashedKey
    if (!Buffer.isBuffer(bufferKey)) bufferKey = fromHash(bufferKey)
    return crypto.subtle.importKey('raw', bufferKey, { name: 'AES-CTR' }, true, ['encrypt', 'decrypt'])
  },

  encryptedToHashed(encrypted, counter) {
    return toHash(Buffer.concat([counter, new Uint8Array(encrypted)]))
  },

  hashedToEncryptedAndCounter(hashed, counterLength = 16) {
    const buffer = Buffer.from(hashed.toString('hex'), 'hex')
    const counter = buffer.slice(0, counterLength)
    const encrypted = buffer.slice(counterLength)
    return { counter, encrypted }
  },

  async encrypt(key, data, counter) {
    if (!counter) counter = await generateCounter()
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-CTR', counter, length: 128 }, key, encode(data))
    const hashed = this.encryptedToHashed(encrypted, counter)
    return hashed
  },

  async decrypt(key, encryptedHash) {
    const { counter, encrypted } = this.hashedToEncryptedAndCounter(encryptedHash)
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-CTR', counter, length: 128 }, key, encrypted)
    const decoded = decode(decrypted)
    return decoded
  },
}

export const RSA = {
  async generateKeyPair() {
    return crypto.subtle.generateKey(
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
    return crypto.subtle.exportKey('jwk', key).then((keyObj) => toHash(Buffer.from(JSON.stringify(keyObj))))
  },

  async exportKeyPair(keyPair) {
    return {
      publicKey: await this.exportKey(keyPair.publicKey),
      privateKey: await this.exportKey(keyPair.privateKey),
    }
  },

  async importKey(hashedKey, keyUsages = ['encrypt']) {
    const keyObj = JSON.parse(decode(fromHash(hashedKey)))
    return crypto.subtle.importKey('jwk', keyObj, { name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, true, keyUsages)
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
    const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, publicKey, encode(data))
    const hashed = this.encryptedToHashed(encrypted)
    return hashed
  },

  async decrypt(privateKey, encryptedHash) {
    const encrypted = this.hashedToEncrypted(encryptedHash)
    const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, privateKey, encrypted)
    const decoded = decode(decrypted)
    return decoded
  },
}

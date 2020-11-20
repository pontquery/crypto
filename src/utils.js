const crypto = require('@trust/webcrypto')

function decode(buffer) {
  return new TextDecoder().decode(buffer)
}

function encode(data) {
  if (data instanceof Uint8Array) {
    return data
  } else if (typeof data === 'string') {
    return new TextEncoder().encode(data)
  } else if (typeof data === 'object') {
    return new TextEncoder().encode(JSON.stringify(data))
  }
}

function fromHash(hash) {
  return Buffer.from(hash.toString('hex'), 'hex')
}

function toHash(buffer) {
  return buffer.toString('hex').toString('base64')
}

async function generateVector(vectorLength = 12) {
  return crypto.getRandomValues(new Uint8Array(vectorLength))
}

const AES = {
  // KEY
  async generateKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  },
  async exportKey(key) {
    return crypto.subtle.exportKey('raw', key).then(toHash)
  },
  async importKey(hashedKey) {
    let bufferKey = hashedKey
    if (!Buffer.isBuffer(bufferKey)) bufferKey = fromHash(bufferKey)
    return crypto.subtle.importKey('raw', bufferKey, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
  },

  // Encryption/Decryption
  encryptedToHashed(encrypted, vector) {
    return toHash(Buffer.concat([vector, new Uint8Array(encrypted)]))
  },
  hashedToEncryptedAndVector(hashed) {
    const buffer = Buffer.from(hashed.toString('hex'), 'hex')
    const vector = buffer.slice(0, 12)
    const encrypted = buffer.slice(12)
    return { vector, encrypted }
  },
  async encrypt(key, data, vector) {
    if (!vector) vector = await generateVector()
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: vector, tagLength: 128 }, key, encode(data))
    const hashed = this.encryptedToHashed(encrypted, vector)
    return hashed
  },
  async decrypt(key, encryptedHash) {
    const { vector, encrypted } = this.hashedToEncryptedAndVector(encryptedHash)
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: vector, tagLength: 128 }, key, encrypted)
    const decoded = decode(decrypted)
    return decoded
  },
}

// KEY RSA

const RSA = {
  // KEY
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
      public: await this.exportKey(keyPair.publicKey),
      private: await this.exportKey(keyPair.privateKey),
    }
  },
  async importKey(hashedKey, keyUsages = ['encrypt']) {
    let keyObj = JSON.parse(encode(fromHash(hashedKey)))
    return crypto.subtle.importKey('jwk', keyObj, { name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, true, keyUsages)
  },
  async importPublicKey(hashedKey) {
    return this.importKey(hashedKey, ['encrypt'])
  },
  async importPrivateKey(hashedKey) {
    return this.importKey(hashedKey, ['decrypt'])
  },

  // Encryption/Decryption
  encryptedToHashed(encrypted) {
    return toHash(Buffer.from(encrypted, 'hex'))
  },
  hashedToEncryptedAndVector(hashed) {
    return Buffer.from(hashed.toString('hex'), 'hex')
  },
  async encrypt(publicKey, data) {
    const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, publicKey, encode(data))
    const hashed = this.encryptedToHashed(encrypted)
    return hashed
  },
  async decrypt(privateKey, encryptedHash) {
    const encrypted = this.hashedToEncryptedAndVector(encryptedHash)
    const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, privateKey, encrypted)
    const decoded = decode(decrypted)
    return decoded
  },
}

module.exports = { AES, RSA }

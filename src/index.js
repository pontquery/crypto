import { RSA, AES } from './utils'

// Client
export class CryptoClient {
  hashedKey = null
  hashedPublicKey = null
  constructor(hashedKey) {
    if (hashedKey) {
      this.hashedKey = hashedKey
    }
  }

  async init() {
    if (!this.hashedKey) {
      const key = await AES.generateKey()
      this.hashedKey = await AES.exportKey(key)
    }
  }

  setPublicKey(hashedPublicKey) {
    this.hashedPublicKey = hashedPublicKey
  }

  /**
   * Used to send the AES key to the server securely using the provided RSA PublicKey
   * @param {*} hashedPublicKey
   */
  async encryptKey() {
    const publicKey = await RSA.importPublicKey(this.hashedPublicKey)
    return RSA.encrypt(publicKey, this.hashedKey)
  }

  /**
   * Used to encrypt the body with the AES key to let the server securely read it
   * @param {*} hashedPublicKey
   * @param {*} body
   */
  async encryptBody(body) {
    const publicKey = await RSA.importPublicKey(this.hashedPublicKey)
    return RSA.encrypt(publicKey, body)
  }

  /**
   * Used to decrypt the body with the AES key (safely encrypted by the server)
   * @param {*} encryptedBody
   */
  async decrypteBody(encryptedBody) {
    const key = await AES.importKey(this.hashedKey)
    return AES.decrypt(key, encryptedBody)
  }
}

export class CryptoServer {
  hashedKey = null
  hashedPublicKey = null
  hashedPrivateKey = null
  constructor({ hashedPublicKey, hashedPrivateKey, hashedKey } = {}) {
    if (hashedPublicKey) this.hashedPublicKey = hashedPublicKey
    if (hashedPrivateKey) this.hashedPrivateKey = hashedPrivateKey
    if (hashedKey) this.hashedKey = hashedKey
  }

  async init() {
    if (!this.hashedPublicKey || !this.hashedPrivateKey) {
      const keyPair = await RSA.generateKeyPair()
      const { publicKey, privateKey } = await RSA.exportKeyPair(keyPair)
      this.hashedPublicKey = publicKey
      this.hashedPrivateKey = privateKey
    }
  }

  async setKey(encryptedHashedKey) {
    const privateKey = await RSA.importPrivateKey(this.hashedPrivateKey)
    const decryptedKey = await RSA.decrypt(privateKey, encryptedHashedKey)
    this.hashedKey = decryptedKey
  }

  async decryptBody(encryptedBody) {
    const privateKey = await RSA.importPrivateKey(this.hashedPrivateKey)
    return RSA.decrypt(privateKey, encryptedBody)
  }

  async encryptBody(body) {
    const key = await AES.importKey(this.hashedKey)
    return AES.encrypt(key, body)
  }
}

export { RSA, AES }

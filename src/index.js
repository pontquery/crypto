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

  /**
   * Save the public key provided by the server
   * @param {*} hashedPublicKey
   */
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

  /**
   * Save the key provided by the client
   * @param {*} encryptedHashedKey
   */
  async setKey(encryptedHashedKey) {
    const privateKey = await RSA.importPrivateKey(this.hashedPrivateKey)
    const decryptedKey = await RSA.decrypt(privateKey, encryptedHashedKey)
    this.hashedKey = decryptedKey
  }

  /**
   * Decrypt body encrypted by the client with the public key
   * @param {*} encryptedBody 
   */
  async decryptBody(encryptedBody) {
    const privateKey = await RSA.importPrivateKey(this.hashedPrivateKey)
    return RSA.decrypt(privateKey, encryptedBody)
  }

  /**
   * Encrypt the body to be sent to the client with the client provided key
   * @param {*} body 
   */
  async encryptBody(body) {
    const key = await AES.importKey(this.hashedKey)
    return AES.encrypt(key, body)
  }

  /**
   * The hashedUserKey would be provided (after a self decryption from a top level key)
   * @param {*} hashedUserKey
   * @param {*} data
   */
  async encryptUserData(hashedUserKey, data) {
    const userKey = await AES.importKey(hashedUserKey)
    return AES.encrypt(userKey, data)
  }

  /**
   * The hashedUserKey would be provided (after a self decryption from a top level key)
   * @param {*} hashedUserKey
   * @param {*} encryptedData
   */
  async decryptUserData(hashedUserKey, encryptedData) {
    const userKey = await AES.importKey(hashedUserKey)
    return AES.decrypt(userKey, encryptedData)
  }
}

export { RSA, AES }

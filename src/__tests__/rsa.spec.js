import { RSA } from '../index'

describe('RSA', () => {
  it('should properly encrypt/decrypt an object', async () => {
    const value = {
      menu: {
        id: 'file',
        value: 'File',
        popup: {
          menuitem: [
            { value: 'New', onclick: 'CreateNewDoc()' },
            { value: 'Open', onclick: 'OpenDoc()' },
            { value: 'Close', onclick: 'CloseDoc()' },
          ],
        },
      },
    }
    const keyPair = await RSA.generateKeyPair()
    const encrypted = await RSA.encrypt(keyPair.publicKey, value)
    const decrypted = await RSA.decrypt(keyPair.privateKey, encrypted)

    expect(value).toEqual(JSON.parse(decrypted))
  })

  it('should properly encrypt/decrypt a string', async () => {
    const value = 'Superbe longue phrase!'
    const keyPair = await RSA.generateKeyPair()
    const encrypted = await RSA.encrypt(keyPair.publicKey, value)
    const decrypted = await RSA.decrypt(keyPair.privateKey, encrypted)

    expect(value).toEqual(decrypted)
  })

  it('should properly encrypt/decrypt a string with an export/imported private key', async () => {
    const value = 'Superbe longue phrase!'
    const keyPair = await RSA.generateKeyPair()
    const encrypted = await RSA.encrypt(keyPair.publicKey, value)
    const exportedPrivateKey = await RSA.exportKey(keyPair.privateKey)
    const importedPrivateKey = await RSA.importPrivateKey(exportedPrivateKey)
    const decrypted = await RSA.decrypt(importedPrivateKey, encrypted)

    expect(value).toEqual(decrypted)
  })

  it('should properly encrypt/decrypt a string with an export/imported public key', async () => {
    const value = 'Superbe longue phrase!'
    const keyPair = await RSA.generateKeyPair()
    const exportedPublicKey = await RSA.exportKey(keyPair.publicKey)
    const importedPublicKey = await RSA.importPublicKey(exportedPublicKey)
    const encrypted = await RSA.encrypt(importedPublicKey, value)
    const decrypted = await RSA.decrypt(keyPair.privateKey, encrypted)

    expect(value).toEqual(decrypted)
  })
})

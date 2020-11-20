import { RSA } from '../utils'

describe('RSA', () => {
  it('should properly encrypt/decrypt a string', async () => {
    const obj = {
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
    const encrypted = await RSA.encrypt(keyPair.publicKey, obj)
    const decrypted = await RSA.decrypt(keyPair.privateKey, encrypted)

    expect(obj).toBe(JSON.parse(decrypted))
  })
})

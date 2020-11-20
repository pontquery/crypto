import { AES } from '../index'

describe('AES', () => {
  it('should properly encrypt/decrypt an object', async () => {
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
    const key = await AES.generateKey()
    const encrypted = await AES.encrypt(key, obj)
    const decrypted = await AES.decrypt(key, encrypted)

    expect(obj).toEqual(JSON.parse(decrypted))
  })

  it('should properly encrypt/decrypt a string', async () => {
    const obj = 'Superbe longue phrase!'
    const key = await AES.generateKey()
    const encrypted = await AES.encrypt(key, obj)
    const decrypted = await AES.decrypt(key, encrypted)

    expect(obj).toEqual(decrypted)
  })

  it('should export/import the key properly', async () => {
    const key = await AES.generateKey()
    const exportedKey = await AES.exportKey(key)
    const importedKey = await AES.importKey(exportedKey)
    expect(key).toEqual(importedKey)
  })
})

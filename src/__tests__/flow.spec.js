import { CryptoClient, CryptoServer } from '../index'

describe('flow', () => {
  it('should handle a complete HTTP exchange', async () => {
    const client = new CryptoClient()
    await client.init()

    const server = new CryptoServer()
    await server.init()

    // send public key to client
    client.setPublicKey(server.hashedPublicKey)

    // prepare client key to be sent
    const encryptedClientKey = await client.encryptKey()

    // send encrypted client key to server
    await server.setKey(encryptedClientKey)

    const body = {
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

    // encrypts body and sends it
    const encryptedBody = await client.encryptBody(body)

    // receives encrypted body
    const decryptedBody = await server.decryptBody(encryptedBody)

    // Body should be equal to the decrypted body
    expect(body).toEqual(JSON.parse(decryptedBody))
  })
})

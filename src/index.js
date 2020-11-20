const { RSA, AES } = require('./utils')

// const run = async () => {
//   const key = await generateKey()
//   const exportedKey = await exportKey(key)
//   const obj = { super: 'ça' }
//   const encrypted = await encrypt(key, JSON.stringify(obj))
//   const decrypted = await decrypt(key, encrypted)
//   console.log('exportedKey', exportedKey)
//   console.log('encrypted', encrypted)
//   console.log('decrypted', JSON.parse(decrypted))
// }

const run = async () => {
  const keyPair = await RSA.generateKeyPair()
  const exportedPublicKey = await RSA.exportKey(keyPair.publicKey)
  const importedPublicKey = await RSA.importKey(exportedPublicKey)
  // console.log(exportedPublicKey)
  // console.log(importedPublicKey)
  const obj = { super: 'ça', ok: "mais" }
  const encrypted = await RSA.encrypt(importedPublicKey, obj)
  console.log('encrypted', encrypted)
  const decrypted = await RSA.decrypt(keyPair.privateKey, encrypted)

  console.log('decrypted', JSON.parse(decrypted))
}

run()

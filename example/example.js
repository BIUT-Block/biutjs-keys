const SecUtils = require('@sec-block/secjs-util')
const utils = new SecUtils()

const SecKeys = require('../src/index.js')
const keySEC = new SecKeys()

const constants = {
  // Symmetric cipher for private key encryption
  cipher: 'aes-128-ctr',

  // Initialization vector size in bytes
  ivBytes: 16,

  // ECDSA private key size in bytes
  keyBytes: 32,

  // Key derivation function parameters
  pbkdf2: {
    c: 262144,
    dklen: 32,
    hash: 'sha256',
    prf: 'hmac-sha256'
  },
  scrypt: {
    memory: 280000000,
    dklen: 32,
    n: 262144,
    r: 1,
    p: 8
  }
}

//  get SEC privateKey 32bit hex
const privateKey = utils.getPrivateKey()
console.log('secPrivateKey:', privateKey)

// let ethPrivateKey = privateKey.slice(0, 32) //  get eth privateKey 32 hex
// console.log('ethPrivateKey:', ethPrivateKey)

// key creation
keySEC.create(constants, (value, err) => {
  if (err) {
    console.log('error occurs')
    console.log(err)
  } else {
    console.log('private key, initialization vector and salt (for key derivation)')
    console.log(value)
  }
})
// convert SEC privateKey to SEC address
let address1 = keySEC.privateKeyToAddress(privateKey).toString('hex')
console.log('secAdress:', address1)

// Export key in a keystore file
let keyObject =
{
  address: address1,
  Crypto: {
    cipher: 'aes-128-ctr',
    ciphertext: '5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46',
    cipherparams: {
      iv: '6087dab2f9fdbbfaddc31a909735c1e6'
    },
    mac: '517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2',
    kdf: 'pbkdf2',
    kdfparams: {
      c: 262144,
      dklen: 32,
      prf: 'hmac-sha256',
      salt: 'ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd'
    }
  },
  id: 'e13b209c-3b2f-4327-bab0-3bef2e51630d',
  version: 3
}

keySEC.exportToFile(keyObject, '', (value, err) => {
  if (err) {
    console.log('error occurs')
    console.log(err)
  } else {
    console.log('Save successfully to File:')
    console.log(value)
  }
})

// Import key from a keystore file

const datadir = ''
let address = address1

keySEC.importFromFile(address, datadir, (value, err) => {
  if (err) {
    console.log('error occurs')
    console.log(err)
  } else {
    console.log('Import from File successfully the Key:')
    console.log(value)
  }
})

let password = ''

keySEC.recover(password, keyObject, (value, err) => {
  if (err) {
    console.log('error occurs')
    console.log(err)
  } else {
    console.log('recover the privateKey')
    console.log(value)
  }
})

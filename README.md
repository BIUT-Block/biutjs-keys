<a name="secKeyStore"></a>

* * *
## secKeyStore
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)]


secKeyStore is a JavaScript tool to generate, import and export SEC keys.  This provides a simple way to use the same account locally and in web wallets.  It can be used for verifiable cold storage wallets.

secKeyStore uses key derivation functions (PBKDF2-SHA256 or scrypt) to genrate decryptionkey,uses Hash function(SHA3-256) to verfify the password and uses the symmetric ciphers (AES-128-CTR or AES-128-CBC) to derive decrypted SEC privateKey. You can export your generated key to file, copy it to your data directory's keystore, and immediately start using it in your local SEC client.

## Installation

```
npm install @sec-block/secjs-keys
```

## Usage

```javascript
const secKeys = require("@sec-block/secjs-keys")
```

### Key creation

Generate a SEC private key (256 bit), as well as the salt (256 bit) used by the key derivation function, and the initialization vector (128 bit) used to AES-128-CTR encrypt the key.  `create` is asynchronous if it is passed a callback function, and synchronous otherwise.

```javascript
// optional private key and initialization vector sizes in bytes
// (if params is not passed to create, secKeys.constants is used by default which is defined in ..src/index.js)
const params = { keyBytes: 32, ivBytes: 16 }

// synchronous
const dk = secKeys.create(params)
// dk: derived key
{
    privateKey: <Buffer ...>,
    iv: <Buffer ...>,
    salt: <Buffer ...>
}

// asynchronous
secKeys.create(params, function (dk) {
    // do stuff!
})
```

### Key export

You will need to specify a password and (optionally) a key derivation function.  If unspecified, PBKDF2-SHA256 will be used to derive the AES secret key.

```javascript
const password = "SECpassword"
const kdf = "pbkdf2" // or "scrypt" to use the scrypt kdf
```

The `dump` function is used to export key info to keystore. If a callback function is supplied as the sixth parameter to `dump`, it will run asynchronously:

```javascript
// Note: if options is unspecified, the values in keythereum.constants are used.
const options = {
  kdf: "pbkdf2", // key derivation function
  cipher: "aes-128-ctr", // cipher function to encrypt private key
  kdfparams: {
    c: 262144,
    dklen: 32,
    prf: "hmac-sha256"
  }
}

// synchronous
let keyObject = secKeys.dump(password, dk.privateKey, dk.salt, dk.iv, options)
// contents of keyObject:
{
  address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
  Crypto: {
    cipher: "aes-128-ctr",
    ciphertext: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
    cipherparams: {
      iv: "6087dab2f9fdbbfaddc31a909735c1e6"
    },
    mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2",
    kdf: "pbkdf2",
    kdfparams: {
      c: 262144,
      dklen: 32,
      prf: "hmac-sha256",
      salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
    }
  },
  id: "e13b209c-3b2f-4327-bab0-3bef2e51630d",
  version: 3
}

// asynchronous
secKeys.dump(password, dk.privateKey, dk.salt, dk.iv, options, function (keyObject) {
  // do stuff!
})
```

`dump` creates an object and not a JSON string. In Node, the `exportToFile` method provides an easy way to export this formatted key object to file.  It creates a JSON file in the `keystore` sub-directory with current file-naming convention (ISO timestamp concatenated with the key's derived SEC address).

```javascript
secKeys.exportToFile(keyObject)
```

After successful key export, you will see a message like:

```
Saved to file:
keystore/UTC--2018-08-22T06:13:53.359Z--008aeeda4d805471df9b2a5b0f38a0c3bcba786b
```

### Key import

Importing a key from keystore can only be done on Node.  The JSON file is parsed into an object with the same structure as `keyObject` above.

```javascript
// Specify a data directory (optional: defaults to ~/.sec)
const datadir = ""

// Synchronous
const keyObject = secKeys.importFromFile(address, datadir)

// Asynchronous
secKeys.importFromFile(address, datadir, function (keyObject) {
  // do stuff
})
```
This has been tested with version 3 and version 1, but not version 2, keys.  (Please send me a version 2 keystore file if you have one, so I can test it!)

To recover the plaintext private key from the key object, use `secKeys.recover`.  The private key is returned as a Buffer.

```javascript
// synchronous
let privateKey = secKeys.recover(password, keyObject)
// privateKey:
<Buffer ...>

// Asynchronous
secKeys.recover(password, keyObject, function (privateKey) {
  // do stuff
})
```


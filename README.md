<a name="secKeyStore"></a>

* * *
## secKeyStore
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 

secKeyStore is a JavaScript tool to generate, import and export SEC keys.  This provides a simple way to use the same account locally and in web wallets.  It can be used for verifiable cold storage wallets.

secKeyStore uses key derivation functions (PBKDF2-SHA256 or scrypt) to genrate decryptionkey,uses Hash function(SHA3-256) to verfify the password and uses the symmetric ciphers (AES-128-CTR or AES-128-CBC) to derive decrypted SEC privateKey. You can export your generated key to file, copy it to your data directory's keystore, and immediately start using it in your local SEC client.

## Installation

```
npm install @sec-block/secjs-keystore
```
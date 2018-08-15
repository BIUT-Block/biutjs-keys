const secUtils = require('@sec-block/secjs-util')
const utils = new secUtils()
const isBrowser = typeof process === "undefined" || !process.nextTick || Boolean(process.browser)
const sjcl = require("sjcl")
const uuid = require("uuid")
const secp256k1 = require("secp256k1/elliptic")
const createKeccakHash = require("keccak/js")
const crypto = isBrowser ? require("crypto-browserify") : require("crypto")

const secKeys = require("../src/index.js")
const keySEC = new secKeys()

const constants = {
    // Symmetric cipher for private key encryption
    cipher: "aes-128-ctr",

    // Initialization vector size in bytes
    ivBytes: 16,

    // ECDSA private key size in bytes
    keyBytes: 32,

    // Key derivation function parameters
    pbkdf2: {
        c: 262144,
        dklen: 32,
        hash: "sha256",
        prf: "hmac-sha256"
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
a = console.log('privateKey:', privateKey)
//  get eth privateKey 32hex 
let ethPrivateKey = privateKey.slice(0, 32)
b = console.log('ethPrivateKey:', ethPrivateKey)

let x = keySEC.create(constants, (err, value) => {
    if (err) {
        console.log('private key, initialization vector and salt (for key derivation)',err) // 'error occurs:',
    } else {
        console.log(value)
    }
})

// let iv x.iv 
console.log(keySEC.isHex(privateKey))

//  create initialization vector and salt (for key derivation).
// c = keySEC.create(cb)
// console.log(c)






//const derivedKey = keySEC.deriveKey(bi7012xiao, )
// b= console.log('deriveKey:',derivedKey)


// const version = "1.0.4",

//  const browser = isBrowser,

// const scrypt = null,



// a= console.log('crypto'+ crypto)

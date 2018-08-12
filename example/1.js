const secUtils = require('@sec-block/secjs-util')
const utils = new secUtils
const isBrowser = typeof process === "undefined" || !process.nextTick || Boolean(process.browser)
const sjcl = require("sjcl")
const uuid = require("uuid")
const secp256k1 = require("secp256k1/elliptic")
const createKeccakHash = require("keccak/js")

const secKeys = require("../src/index.js")
const keySEC = new secKeys()


const privateKey = utils.generatePrivateKey()
// function isFunction (f) {
//     return typeof f === "function"
// }
// function keccak256 (buffer) {
//     return createKeccakHash("keccak256").update(buffer).digest()
// }

// const version = "1.0.4",

//  const browser = isBrowser,

// const scrypt = null,

const crypto = isBrowser ? require("crypto-browserify") : require("crypto"),

a= console.log('crypto'+ crypto)
b= console.log('privateKey'+privateKey)


// console.log(a)

const secUtils = require('@sec-block/secjs-util')
const utils = new secUtils
const isBrowser = typeof process === "undefined" || !process.nextTick || Boolean(process.browser)
const sjcl = require("sjcl")
const uuid = require("uuid")
const secp256k1 = require("secp256k1/elliptic")
const createKeccakHash = require("keccak/js")

function isFunction (f) {
    return typeof f === "function"
}
function keccak256 (buffer) {
    return createKeccakHash("keccak256").update(buffer).digest()
}


class secKeys {
    constructor () {

        const version = "1.0.4",

        const browser = isBrowser,

        const scrypt = null,

        const crypto = isBrowser ? require("crypto-browserify") : require("crypto"),

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
        this.utils = utils
        this.utilsprivateKeyToAddress()
        // generatePrivateKey()
        // generatePublicKey()
        // generateAddress
        // publicToAddress
        // privateToPublic
        // isValidSignature
        this.constants = constants
    }


    isBase64 (str) {
        var index;
        if (str.length % 4 > 0 || str.match(/[^0-9a-z+\/=]/i)) return false;
        index = str.indexOf("=");
        if (index === -1 || str.slice(index).match(/={1,2}/)) return true;
        return false;
    }


    str2buf (str, enc) {
        if (!str || str.constructor !== String) return str;
        if (!enc && this.isHex(str)) enc = "hex";
        if (!enc && this.isBase64(str)) enc = "base64";
        return Buffer.from(str, enc)
    }

    isCipherAvailable (cipher) {
        return this.crypto.getCiphers().some(function (name) { return name === cipher; });
    }

    encrypt (plaintext, key, iv, algo) {
        var cipher, ciphertext
        algo = algo || this.constants.cipher
        if (!this.isCipherAvailable(algo)) throw new Error(algo + " is not available")
        cipher = this.crypto.createCipheriv(algo, this.str2buf(key), this.str2buf(iv))
        ciphertext = cipher.update(this.str2buf(plaintext))
        return Buffer.concat([ciphertext, cipher.final()])
    }

    decrypt (ciphertext, key, iv, algo) {
        var decipher, plaintext;
        algo = algo || this.constants.cipher;
        if (!this.isCipherAvailable(algo)) throw new Error(algo + " is not available");
        decipher = this.crypto.createDecipheriv(algo, this.str2buf(key), this.str2buf(iv));
        plaintext = decipher.update(this.str2buf(ciphertext))
        return Buffer.concat([plaintext, decipher.final()])
    }

    getMAC (derivedKey, ciphertext) {
        if (derivedKey !== undefined && derivedKey !== null && ciphertext !== undefined && ciphertext !== null) {
            return keccak256(Buffer.concat([
                this.str2buf(derivedKey).slice(16, 32),
                this.str2buf(ciphertext)
            ])).toString("hex")
        }
    }

    deriveKeyUsingScryptInNode (password, salt, options, cb) {
        if (!isFunction(cb)) return this.deriveKeyUsingScryptInBrowser(password, salt, options);
        require("scrypt").hash(password, {
            N: options.kdfparams.n || this.constants.scrypt.n,
            r: options.kdfparams.r || this.constants.scrypt.r,
            p: options.kdfparams.p || this.constants.scrypt.p
        }, options.kdfparams.dklen || this.constants.scrypt.dklen, salt).then(cb).catch(cb);
    }

    deriveKeyUsingScryptInBrowser (password, salt, options, cb) {
        var self = this;
        if (this.scrypt === null) this.scrypt = require("./lib/scrypt")
        if (isFunction(this.scrypt)) {
            this.scrypt = this.scrypt(options.kdfparams.memory || this.scrypt.memory);
        }
        if (!isFunction(cb)) {
            return Buffer.from(this.scrypt.to_hex(this.constants.scrypt.crypto_scrypt(
                password,
                salt,
                options.kdfparams.n || this.constants.scrypt.n,
                options.kdfparams.r || this.constants.scrypt.r,
                options.kdfparams.p || this.constants.scrypt.p,
                options.kdfparams.dklen || this.constants.scrypt.dklen
            )), "hex")
        }
        setTimeout(function () {
            cb(Buffer.from(self.scrypt.to_hex(self.scrypt.crypto_scrypt(
                password,
                salt,
                options.kdfparams.n || self.constants.scrypt.n,
                options.kdfparams.r || self.constants.scrypt.r,
                options.kdfparams.p || self.constants.scrypt.p,
                options.kdfparams.dklen || self.constants.scrypt.dklen
            )), "hex"))
        }, 0)
    }
    deriveKey (password, salt, options, cb) {
        var prf, self = this;
        if (typeof password === "undefined" || password === null || !salt) {
            throw new Error("Must provide password and salt to derive a key");
        }
        options = options || {};
        options.kdfparams = options.kdfparams || {};

        // convert strings to buffers
        password = this.str2buf(password, "utf8");
        salt = this.str2buf(salt);

        // use scrypt as key derivation function
        if (options.kdf === "scrypt") {
            if (!this.browser) return this.deriveKeyUsingScryptInNode(password, salt, options, cb);
            return this.deriveKeyUsingScryptInBrowser(password, salt, options, cb);
        }

        // use default key derivation function (PBKDF2)
        prf = options.kdfparams.prf || this.constants.pbkdf2.prf;
        if (prf === "hmac-sha256") prf = "sha256";
        if (!isFunction(cb)) {
            if (!this.crypto.pbkdf2Sync) {
                return Buffer.from(sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(
                    password.toString("utf8"),
                    sjcl.codec.hex.toBits(salt.toString("hex")),
                    options.kdfparams.c || self.constants.pbkdf2.c,
                    (options.kdfparams.dklen || self.constants.pbkdf2.dklen) * 8
                )), "hex");
            }
            return this.crypto.pbkdf2Sync(
                password,
                salt,
                options.kdfparams.c || this.constants.pbkdf2.c,
                options.kdfparams.dklen || this.constants.pbkdf2.dklen,
                prf
            );
        }
        if (!this.crypto.pbkdf2) {
            setTimeout(function () {
                cb(Buffer.from(sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(
                    password.toString("utf8"),
                    sjcl.codec.hex.toBits(salt.toString("hex")),
                    options.kdfparams.c || self.constants.pbkdf2.c,
                    (options.kdfparams.dklen || self.constants.pbkdf2.dklen) * 8
                )), "hex"));
            }, 0);
        } else {
            this.crypto.pbkdf2(
                password,
                salt,
                options.kdfparams.c || this.constants.pbkdf2.c,
                options.kdfparams.dklen || this.constants.pbkdf2.dklen,
                prf,
                function (ex, derivedKey) {
                    if (ex) return cb(ex);
                    cb(derivedKey);
                }
            );
        }
    }


    create (params, cb) {
        var keyBytes, ivBytes, self = this;
        params = params || {};
        keyBytes = params.keyBytes || this.constants.keyBytes;
        ivBytes = params.ivBytes || this.constants.ivBytes;

        function checkBoundsAndCreateObject (randomBytes) {
            var privateKey = randomBytes.slice(0, keyBytes);
            if (!secp256k1.privateKeyVerify(privateKey)) return self.create(params, cb);
            return {
                privateKey: privateKey,
                iv: randomBytes.slice(keyBytes, keyBytes + ivBytes),
                salt: randomBytes.slice(keyBytes + ivBytes)
            };
        }

        // synchronous key generation if callback not provided
        if (!isFunction(cb)) {
            return checkBoundsAndCreateObject(this.crypto.randomBytes(keyBytes + ivBytes + keyBytes));
        }

        // asynchronous key generation
        this.crypto.randomBytes(keyBytes + ivBytes + keyBytes, function (err, randomBytes) {
            if (err) return cb(err);
            cb(checkBoundsAndCreateObject(randomBytes));
        });
    }


    marshal (derivedKey, privateKey, salt, iv, options) {
        var ciphertext, keyObject, algo;
        options = options || {};
        options.kdfparams = options.kdfparams || {};
        algo = options.cipher || this.constants.cipher;

        // encrypt using first 16 bytes of derived key
        ciphertext = this.encrypt(privateKey, derivedKey.slice(0, 16), iv, algo).toString("hex");

        keyObject = {
            address: this.utils.privateKeyToAddress(privateKey).slice(2),
            crypto: {
                cipher: options.cipher || this.constants.cipher,
                ciphertext: ciphertext,
                cipherparams: { iv: iv.toString("hex") },
                mac: this.getMAC(derivedKey, ciphertext)
            },
            id: uuid.v4(), // random 128-bit UUID
            version: 3
        }

        if (options.kdf === "scrypt") {
            keyObject.crypto.kdf = "scrypt";
            keyObject.crypto.kdfparams = {
                dklen: options.kdfparams.dklen || this.constants.scrypt.dklen,
                n: options.kdfparams.n || this.constants.scrypt.n,
                r: options.kdfparams.r || this.constants.scrypt.r,
                p: options.kdfparams.p || this.constants.scrypt.p,
                salt: salt.toString("hex")
            };

        } else {
            keyObject.crypto.kdf = "pbkdf2";
            keyObject.crypto.kdfparams = {
                c: options.kdfparams.c || this.constants.pbkdf2.c,
                dklen: options.kdfparams.dklen || this.constants.pbkdf2.dklen,
                prf: options.kdfparams.prf || this.constants.pbkdf2.prf,
                salt: salt.toString("hex")
            };
        }

        return keyObject;
    }


    dump (password, privateKey, salt, iv, options, cb) {
        options = options || {};
        iv = this.str2buf(iv);
        privateKey = this.str2buf(privateKey);

        // synchronous if no callback provided
        if (!isFunction(cb)) {
            return this.marshal(this.deriveKey(password, salt, options), privateKey, salt, iv, options);
        }

        // asynchronous if callback provided
        this.deriveKey(password, salt, options, function (derivedKey) {
            cb(this.marshal(derivedKey, privateKey, salt, iv, options));
        }.bind(this));
    }


    recover (password, keyObject, cb) {
        var keyObjectCrypto, iv, salt, ciphertext, algo, self = this;
        keyObjectCrypto = keyObject.Crypto || keyObject.crypto;

        // verify that message authentication codes match, then decrypt
        function verifyAndDecrypt (derivedKey, salt, iv, ciphertext, algo) {
            var key;
            if (self.getMAC(derivedKey, ciphertext) !== keyObjectCrypto.mac) {
                throw new Error("message authentication code mismatch");
            }
            if (keyObject.version === "1") {
                key = keccak256(derivedKey.slice(0, 16)).slice(0, 16);
            } else {
                key = derivedKey.slice(0, 16);
            }
            return self.decrypt(ciphertext, key, iv, algo);
        }

        iv = this.str2buf(keyObjectCrypto.cipherparams.iv);
        salt = this.str2buf(keyObjectCrypto.kdfparams.salt);
        ciphertext = this.str2buf(keyObjectCrypto.ciphertext);
        algo = keyObjectCrypto.cipher;

        if (keyObjectCrypto.kdf === "pbkdf2" && keyObjectCrypto.kdfparams.prf !== "hmac-sha256") {
            throw new Error("PBKDF2 only supported with HMAC-SHA256");
        }

        // derive secret key from password
        if (!isFunction(cb)) {
            return verifyAndDecrypt(this.deriveKey(password, salt, keyObjectCrypto), salt, iv, ciphertext, algo);
        }
        this.deriveKey(password, salt, keyObjectCrypto, function (derivedKey) {
            try {
                cb(verifyAndDecrypt(derivedKey, salt, iv, ciphertext, algo));
            } catch (exc) {
                cb(exc);
            }
        })
    }

    generateKeystoreFilename (address) {
        var filename = "UTC--" + new Date().toISOString() + "--" + address;

        // Windows does not permit ":" in filenames, replace all with "-"
        if (process.platform === "win32") filename = filename.split(":").join("-");

        return filename;
    }


    exportToFile (keyObject, keystore, cb) {
        var outfile, outpath, json, fs;
        keystore = keystore || "keystore";
        outfile = this.generateKeystoreFilename(keyObject.address)
        json = JSON.stringify(keyObject);
        if (this.browser) {
            if (!isFunction(cb)) return json;
            return cb(json)
        }
        outpath = require("path").join(keystore, outfile)
        fs = require("fs");
        if (!isFunction(cb)) {
            fs.writeFileSync(outpath, json);
            return outpath
        }
        fs.writeFile(outpath, json, function (err) {
            if (err) return cb(err);
            cb(outpath)
        })
    }
    importFromFile (address, datadir, cb) {
        var keystore, filepath, path, fs;
        if (this.browser) throw new Error("method only available in Node.js");
        path = require("path");
        fs = require("fs");
        address = address.replace("0x", "");
        address = address.toLowerCase();

        function findKeyfile (keystore, address, files) {
            var i, len, filepath = null;
            for (i = 0, len = files.length; i < len; ++i) {
                if (files[i].indexOf(address) > -1) {
                    filepath = path.join(keystore, files[i]);
                    if (fs.lstatSync(filepath).isDirectory()) {
                        filepath = path.join(filepath, files[i]);
                    }
                    break
                }
            }
            return filepath
        }

        datadir = datadir || path.join(process.env.HOME, ".ethereum");
        keystore = path.join(datadir, "keystore");
        if (!isFunction(cb)) {
            filepath = findKeyfile(keystore, address, fs.readdirSync(keystore));
            if (!filepath) {
                throw new Error("could not find key file for address " + address);
            }
            return JSON.parse(fs.readFileSync(filepath));
        }
        fs.readdir(keystore, function (ex, files) {
            var filepath;
            if (ex) return cb(ex);
            filepath = findKeyfile(keystore, address, files);
            if (!filepath) {
                return new Error("could not find key file for address " + address);
            }
            return cb(JSON.parse(fs.readFileSync(filepath)));
        })
    }
}

module.exports = secKeys

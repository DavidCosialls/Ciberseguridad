'use strict';
// const encrypt = (str) => {
//   const reverse = str.split('').reverse().join('')
//   return 'encrypted_' + reverse
// }
// const decrypt = (str) => {
//   const strip = str.substr(10)  // Let us remove the 'encrypted_' part
//   return strip.split('').reverse().join('')
// }
const paillierBigint = require('paillier-bigint')

const sss = require('shamirs-secret-sharing')
const secret = Buffer.from('secret key')
const shares = sss.split(secret, { shares: 10, threshold: 4 })
const recovered = sss.combine(shares.slice(3, 7))

const bcu = require("bigint-crypto-utils")
class RsaPublicKey {
    constructor(e,n){
            this.e = e;
            this.n = n;
    }
    encrypt(m) {
      const c = bcu.modPow(m, this.e, this.n)
      return c
    }
    verify(s) {
      return bcu.modPow(s, this.e, this.n)
    }
}

class RsaPrivateKey {
  constructor(d,n){
          this.d = d;
          this.n = n;
  }
  decrypt(c) { 
    return bcu.modPow(c, this.d, this.n)
  }
  sign(m) {
    return bcu.modPow(m, this.d, this.n)
  }
}

async function generateRSAKey (bitlength){
  const e = 65537n 
  let n, p, q, phin, r
  do {
    p = await bcu.prime(Math.floor(bitlength/2) + 1)
    q = await bcu.prime(Math.floor(bitlength/2))
    n = p*q
    
    
    phin = (p-1n)*(q-1n) 
  } while (bcu.bitLength(n) !== bitlength || phin % e === 0n)
  const d = bcu.modInv(e, phin) //Calculating the d for the RSA:private
  

  const publicKey = new RsaPublicKey(e, n)
  const privateKey = new RsaPrivateKey(d, n) 
  
  return {
    publicKey: publicKey,
    privateKey: privateKey,
  }
}

function blind(m, publicKey, privateKey){
  let r
  do {
    r = bcu.randBetween(publicKey.n-1n, 1n)
  }while (bcu.gcd(r, publicKey.n) !== 1n)
  console.log(bcu.gcd(r, publicKey.n))
  
  const blindmessage = publicKey.encrypt(r) * m % publicKey.n
  const sign = privateKey.sign(blindmessage)
  const unblind = sign * bcu.modInv(r, publicKey.n)
  if (publicKey.verify(unblind) === m){
    console.log("blinded correctly")
  }else{
    console.log("Not blinded")
  }
  return{
    blindmessage: blindmessage,
    sign: sign
  }
}





// exports.encrypt = encrypt
// exports.decrypt = decrypt
exports.RsaPublicKey = RsaPublicKey
exports.RsaPrivateKey = RsaPrivateKey
exports.blind = blind
exports.generateRSAKey = generateRSAKey
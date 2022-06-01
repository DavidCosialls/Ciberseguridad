const bcu = require('bigint-crypto-utils')
const myrsa = require('./index.js')
const bitlength = 1024
const main = async function(){
  const keypair = await myrsa.generateRSAKey(bitlength)
  const m = bcu.randBetween(keypair.publicKey.n - 1n)
  //console.log("m: ", m)
  const c = keypair.publicKey.encrypt(m)
  //console.log(c)
  const d = keypair.privateKey.decrypt(c)

  
  

  if (m!==d){
    console.log("Error")
  }else{
    console.log("Working")
    //console.log(m)
  }

  myrsa.blind(m, keypair.publicKey, keypair.privateKey)
  //const m_blinded = keypair.blindMessage.blind(m)
  //console.log("m_blind: ", m_blinded)
  //const signed = keypair.blindMessage.sign(m_blinded)
  //console.log("signed: ", signed)
  //const unblinded = keypair.blindMessage.unblind(signed)
  //console.log("unblinded: ", unblinded)
  //keypair.blindMessage.verify(unblinded, m);
  
  
}
main()
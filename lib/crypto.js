const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

function hash(data) {
  const out = b4a.allocUnsafe(32)
  sodium.crypto_generichash(out, data)
  return out
}

function unslabbedHash(data) {
  const out = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(out, data)
  return out
}

function createKeyPair(seed) {
  // Use hypercore-crypto (which uses red25519) instead of sodium
  return crypto.keyPair(seed)
}

module.exports = {
  hash,
  unslabbedHash,
  createKeyPair
}

const test = require('brittle')
const StandardHyperDHT = require('hyperdht-standard')
const DHT = require('../index.js')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')
const m = require('../lib/messages.js')
const { NS } = require('../lib/constants.js')

// Create a testnet using standard hyperdht
async function createStandardTestnet(size = 10, opts = {}) {
  const swarm = []
  const teardown =
    typeof opts === 'function' ? opts : opts.teardown ? opts.teardown.bind(opts) : noop
  const host = opts.host || '127.0.0.1'
  const port = opts.port || 0
  const bootstrap = opts.bootstrap ? [...opts.bootstrap] : []
  const bindHost = host === '127.0.0.1' ? '127.0.0.1' : '0.0.0.0'
  const includeRed25519 = opts.includeRed25519 || false

  if (size === 0) return new Testnet(swarm)

  // Optionally add a red25519 node first to bootstrap with the network
  let first
  if (includeRed25519) {
    first = new DHT({
      ephemeral: false,
      firewalled: false,
      bootstrap,
      port,
      host: bindHost
    })
  } else {
    first = new StandardHyperDHT({
      ephemeral: false,
      firewalled: false,
      bootstrap,
      port,
      host: bindHost
    })
  }

  await first.fullyBootstrapped()

  if (bootstrap.length === 0) bootstrap.push({ host, port: first.address().port })

  swarm.push(first)

  while (swarm.length < size) {
    const node = new StandardHyperDHT({
      ephemeral: false,
      firewalled: false,
      bootstrap,
      host: bindHost
    })

    await node.fullyBootstrapped()
    swarm.push(node)
  }

  const testnet = new Testnet(swarm, bootstrap)

  teardown(() => testnet.destroy(), { order: Infinity })

  return testnet
}

class Testnet {
  constructor(nodes, bootstrap = []) {
    this.nodes = nodes
    this.bootstrap = bootstrap
  }

  async destroy() {
    for (const node of this.nodes) {
      for (const server of node.listening) await server.close()
    }

    for (let i = this.nodes.length - 1; i >= 0; i--) {
      await this.nodes[i].destroy()
    }
  }
}

function noop() {}

test('standard mutable put - get (baseline test)', async function (t) {
  // Create a swarm of 100 standard hyperdht nodes (ed25519) from npm
  const testnet = await createStandardTestnet(100, { teardown: t.teardown })
  const { nodes } = testnet

  // Use standard hyperdht keyPair (ed25519)
  const keyPair = StandardHyperDHT.keyPair()

  t.comment(
    `Using standard ed25519 keyPair - publicKey length: ${keyPair.publicKey.length}, secretKey length: ${keyPair.secretKey.length}`
  )

  // Put mutable value using standard ed25519 keyPair
  const put = await nodes[30].mutablePut(keyPair, Buffer.from('testing standard'))

  t.is(put.signature.length, 64)
  t.is(put.seq, 0)
  t.ok(Buffer.isBuffer(put.publicKey))
  t.is(put.publicKey.length, 32)

  // Get mutable value using standard public key
  const res = await nodes[3].mutableGet(keyPair.publicKey)

  t.is(res.seq, 0)
  t.is(Buffer.isBuffer(res.value), true)
  t.is(Buffer.compare(res.signature, put.signature), 0)
  t.is(res.value.toString(), 'testing standard')
  t.is(typeof res.from, 'object')
  t.is(typeof res.from.host, 'string')
  t.is(typeof res.from.port, 'number')
})

test('standard mutable put - put - get with sequence (baseline test)', async function (t) {
  const testnet = await createStandardTestnet(100, { teardown: t.teardown })
  const { nodes } = testnet
  const keyPair = StandardHyperDHT.keyPair()

  // First put
  const put = await nodes[30].mutablePut(keyPair, Buffer.from('testing standard'))

  t.is(put.signature.length, 64)
  t.is(put.seq, 0)

  // Second put with higher seq
  const put2 = await nodes[25].mutablePut(keyPair, Buffer.from('testing standard two'), { seq: 2 })

  t.is(put2.signature.length, 64)
  t.is(put2.seq, 2)

  // Get should return the latest (seq 2)
  const res = await nodes[3].mutableGet(keyPair.publicKey)

  t.is(res.seq, 2)
  t.is(Buffer.isBuffer(res.value), true)
  t.is(Buffer.compare(res.signature, put2.signature), 0)
  t.is(res.value.toString(), 'testing standard two')
})

test('standard put - red25519 get', async function (t) {
  // Create a testnet of standard nodes with one red25519 node included
  const testnet = await createStandardTestnet(100, {
    teardown: t.teardown,
    includeRed25519: true
  })
  const { nodes } = testnet

  // The red25519 node is the first node in the array (bootstrap node)
  const red25519Node = nodes[0]
  const standardNode = nodes[1]

  // Use red25519 keyPair from DHT (which uses hypercore-crypto internally)
  const keyPair = DHT.keyPair()
  const standardKeyPair = StandardHyperDHT.keyPair()

  // Put mutable value using red25519 node and red25519 keyPair
  const put = await standardNode.mutablePut(standardKeyPair, Buffer.from('testing standard'))

  t.is(put.signature.length, 64)
  t.is(put.seq, 0)
  t.ok(Buffer.isBuffer(put.publicKey))
  t.is(put.publicKey.length, 32)

  const res2 = await red25519Node.mutableGet(standardKeyPair.publicKey)

  t.is(res2.seq, 0)
  t.is(Buffer.isBuffer(res2.value), true)
  t.is(Buffer.compare(res2.signature, put.signature), 0)
  t.is(res2.value.toString(), 'testing standard')
  t.is(typeof res2.from, 'object')
  t.is(typeof res2.from.host, 'string')
  t.is(typeof res2.from.port, 'number')
})

test('red25519 put - standard get', async function (t) {
  // Create a testnet of standard nodes with one red25519 node included
  const testnet = await createStandardTestnet(100, {
    teardown: t.teardown,
    includeRed25519: true
  })
  const { nodes } = testnet

  // The red25519 node is the first node in the array (bootstrap node)
  const red25519Node = nodes[0]
  const standardNode = nodes[1]

  t.comment(
    `[TEST] Red25519 node: ${red25519Node.constructor.name}, listening: ${red25519Node.listening.size}`
  )
  t.comment(
    `[TEST] Standard node: ${standardNode.constructor.name}, listening: ${standardNode.listening.size}`
  )

  // Use red25519 keyPair from DHT (which uses hypercore-crypto internally)
  const keyPair = DHT.keyPair()
  const standardKeyPair = StandardHyperDHT.keyPair()

  t.comment(
    `[TEST] Red25519 keyPair - publicKey: ${keyPair.publicKey.toString('hex').substring(0, 16)}...`
  )
  t.comment(`[TEST] Starting red25519 mutablePut...`)
  const putStartTime = Date.now()

  let put
  try {
    // Put mutable value using red25519 node and red25519 keyPair
    t.comment(`[TEST] Calling red25519Node.mutablePut()...`)
    put = await red25519Node.mutablePut(keyPair, Buffer.from('testing red25519'))
    const putDuration = Date.now() - putStartTime
    t.comment(
      `[TEST] Red25519 mutablePut succeeded - seq: ${put.seq}, signature length: ${put.signature.length}, duration: ${putDuration}ms`
    )
    t.comment(`[TEST] Closest nodes found: ${put.closestNodes ? put.closestNodes.length : 0}`)
  } catch (err) {
    const putDuration = Date.now() - putStartTime
    t.comment(`[TEST] Red25519 mutablePut FAILED after ${putDuration}ms`)
    t.comment(`[TEST] Error message: ${err.message}`)
    t.comment(`[TEST] Error code: ${err.code}`)
    t.comment(`[TEST] Error name: ${err.name}`)
    if (err.stack) {
      t.comment(`[TEST] Error stack: ${err.stack.split('\n').slice(0, 5).join('\n')}`)
    }
    throw err
  }

  t.is(put.signature.length, 64)
  t.is(put.seq, 0)
  t.ok(Buffer.isBuffer(put.publicKey))
  t.is(put.publicKey.length, 32)

  t.comment(`[TEST] Starting standard node mutableGet...`)
  const getStartTime = Date.now()
  let res2
  try {
    t.comment(
      `[TEST] Calling standardNode.mutableGet() with publicKey: ${keyPair.publicKey.toString('hex').substring(0, 16)}...`
    )
    res2 = await standardNode.mutableGet(keyPair.publicKey)
    const getDuration = Date.now() - getStartTime
    t.comment(
      `[TEST] Standard mutableGet succeeded - seq: ${res2.seq}, value: ${res2.value.toString()}, duration: ${getDuration}ms`
    )
  } catch (err) {
    const getDuration = Date.now() - getStartTime
    t.comment(`[TEST] Standard mutableGet FAILED after ${getDuration}ms`)
    t.comment(`[TEST] Error message: ${err.message}`)
    t.comment(`[TEST] Error code: ${err.code}`)
    t.comment(`[TEST] Error name: ${err.name}`)
    if (err.stack) {
      t.comment(`[TEST] Error stack: ${err.stack.split('\n').slice(0, 5).join('\n')}`)
    }
    throw err
  }

  t.is(res2.seq, 0)
  t.is(Buffer.isBuffer(res2.value), true)
  t.is(Buffer.compare(res2.signature, put.signature), 0)
  t.is(res2.value.toString(), 'testing red25519')
  t.is(typeof res2.from, 'object')
  t.is(typeof res2.from.host, 'string')
  t.is(typeof res2.from.port, 'number')
})

test('red25519 sign - standard verify (direct test)', async function (t) {
  // Test signing with red25519 and verifying with standard sodium
  const red25519KeyPair = DHT.keyPair()
  const seq = 0
  const value = Buffer.from('testing red25519 signature')

  // Sign using red25519 (via crypto.sign)
  const signable = b4a.allocUnsafe(32 + 32)
  const hash = signable.subarray(32)
  signable.set(NS.MUTABLE_PUT, 0)
  sodium.crypto_generichash(hash, c.encode(m.mutableSignable, { seq, value }))
  const signature = crypto.sign(signable, red25519KeyPair.secretKey)

  t.comment(`Red25519 signature created: ${signature.length} bytes`)
  t.is(signature.length, 64)

  // Verify using standard sodium (like standard hyperdht would)
  // Note: sodium may require a normalized (torsion-free) public key
  const verifySignable = b4a.allocUnsafe(32 + 32)
  const verifyHash = verifySignable.subarray(32)
  verifySignable.set(NS.MUTABLE_PUT, 0)
  sodium.crypto_generichash(verifyHash, c.encode(m.mutableSignable, { seq, value }))

  const verifyResult = sodium.crypto_sign_verify_detached(
    signature,
    verifySignable,
    red25519KeyPair.publicKey
  )

  t.comment(`Standard sodium verification result: ${verifyResult}`)
  t.ok(verifyResult, 'Standard sodium should verify red25519 signature')
})

test('standard sign - red25519 verify (direct test)', async function (t) {
  // Test signing with standard sodium and verifying with red25519
  const standardKeyPair = StandardHyperDHT.keyPair()
  const seq = 0
  const value = Buffer.from('testing standard signature')

  // Sign using standard sodium
  const signable = b4a.allocUnsafe(32 + 32)
  const hash = signable.subarray(32)
  signable.set(NS.MUTABLE_PUT, 0)
  sodium.crypto_generichash(hash, c.encode(m.mutableSignable, { seq, value }))
  const signature = b4a.allocUnsafe(64)
  sodium.crypto_sign_detached(signature, signable, standardKeyPair.secretKey)

  t.comment(`Standard signature created: ${signature.length} bytes`)
  t.is(signature.length, 64)

  // Verify using red25519 (via crypto.verify)
  const verifySignable = b4a.allocUnsafe(32 + 32)
  const verifyHash = verifySignable.subarray(32)
  verifySignable.set(NS.MUTABLE_PUT, 0)
  sodium.crypto_generichash(verifyHash, c.encode(m.mutableSignable, { seq, value }))

  const verifyResult = crypto.verify(verifySignable, signature, standardKeyPair.publicKey)

  t.comment(`Red25519 verification result: ${verifyResult}`)
  t.ok(verifyResult, 'Red25519 should verify standard signature')
})

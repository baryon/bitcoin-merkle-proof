const test = require('tape')
const merkleTree = require('../')

const util = require('./util')
const fixtures = require('./fixtures.json')

test('valid', function (t) {
  fixtures.valid.forEach(function (fixture) {
    t.test(fixture.name, function (t) {
      const data = {
        hashes: util.strings2buffers(fixture.txids),
        include: util.strings2buffers(fixture.include),
        merkleRoot: util.string2buffer(fixture.merkleRoot)
      }

      const pmt = merkleTree.build(data)
      const hashes = merkleTree.verify(pmt)

      t.deepEqual(fixture.include, util.buffers2string(hashes))
      t.end()
    })
  })

  t.end()
})

test('valid verify()', function (t) {
  fixtures.validVerify.forEach(function (data) {
    t.test(data.name, function (t) {
      data.hashes = util.strings2buffers(data.hashes)
      data.merkleRoot = util.string2buffer(data.merkleRoot)

      const hashes = merkleTree.verify(data)

      t.deepEqual(data.include, util.buffers2string(hashes))
      t.end()
    })
  })

  t.end()
})

test('invalid', function (t) {
  fixtures.invalid.forEach(function (fixture) {
    t.test(fixture.name, function (t) {
      const pmt = {
        flags: fixture.flags,
        hashes: fixture.hashes.map(function (s) { return Buffer.from(s, 'hex') }),
        numTransactions: fixture.numTransactions,
        merkleRoot: Buffer.from(fixture.merkleRoot, 'hex')
      }

      t.throws(function () {
        merkleTree.verify(pmt)
      }, new RegExp(fixture.message))
      t.end()
    })
  })

  t.end()
})

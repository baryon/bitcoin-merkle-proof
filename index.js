const createHash = require('create-hash')

/**
 * @param {Buffer} buf1
 * @param {Buffer} buf2
 * @return {Buffer}
 */
function hash256 (buf1, buf2) {
  const buf = createHash('sha256').update(buf1).update(buf2).digest()
  return createHash('sha256').update(buf).digest()
}

/**
 * @param {number} numTransactions
 * @return {number} height
 */
function calcTreeWidth (numTransactions, height) {
  return (numTransactions + (1 << height) - 1) >> height
}

/**
 * @param {number[]} bits
 * @return {number[]}
 */
function bits2bytes (bits) {
  const bytes = []
  for (let i = 0; 8 * i < bits.length; ++i) {
    for (let j = 0; j < 8; ++j) {
      bytes[i] |= bits[8 * i + j] << j
    }
  }

  return bytes
}

/**
 * @param {number[]} bytes
 * @return {number[]}
 */
function bytes2bits (bytes) {
  const bits = []
  for (let i = 0; i < bytes.length; ++i) {
    for (let j = 0; j < 8; ++j) {
      bits.push((bytes[i] >>> j) & 0x01)
    }
  }

  return bits
}

/**
 * @typedef {Object} partialMerkleTree
 * @property {number[]} flags
 * @property {Buffer[]} hashes
 * @property {number} numTransactions
 */

/**
 * @param {{hashes: Buffer[], include: Buffer[], merkleRoot: Buffer}} data
 * @return {partialMerkleTree}
 */
module.exports.build = function (data) {
  const numTransactions = data.hashes.length
  const include = data.include.map(function (b) { return b.toString('hex') })
  const match = new Array(numTransactions)
  for (let i = 0; i < match.length; ++i) {
    match[i] = include.indexOf(data.hashes[i].toString('hex')) === -1 ? 0 : 1
  }

  const bits = []
  const hashes = []

  /**
   * @param {number} height
   * @param {number} pos
   * @return {Buffer}
   */
  function getHash (height, pos) {
    if (height === 0) {
      return data.hashes[pos]
    }

    const left = getHash(height - 1, pos * 2)
    if (pos * 2 + 1 < calcTreeWidth(numTransactions, height - 1)) {
      return hash256(left, getHash(height - 1, pos * 2 + 1))
    }

    return hash256(left, left)
  }

  /**
   * @param {number} height
   * @param {number} pos
   */
  function build (height, pos) {
    let parentOfMatch = 0
    for (let p = pos << height, m = (pos + 1) << height; p < m && p < numTransactions; ++p) {
      parentOfMatch |= match[p]
    }
    bits.push(parentOfMatch)

    if (height === 0 || parentOfMatch === 0) {
      return hashes.push(getHash(height, pos))
    }

    build(height - 1, pos * 2)
    if (pos * 2 + 1 < calcTreeWidth(numTransactions, height - 1)) {
      build(height - 1, pos * 2 + 1)
    }
  }

  const height = Math.ceil(Math.log2(data.hashes.length))
  build(height, 0)

  return {
    flags: bits2bytes(bits),
    hashes: hashes,
    numTransactions: numTransactions,
    merkleRoot: getHash(height, 0)
  }
}

/**
 * @param {partialMerkleTree} data
 * @return {Buffer[]}
 */
module.exports.verify = function (data) {
  const hashes = []
  const bits = bytes2bits(data.flags)
  let bitsUsed = 0
  let hashUsed = 0

  /**
   * @param {number} height
   * @param {number} pos
   * @return {Buffer}
   */
  function extract (height, pos) {
    const parentOfMatch = bits[bitsUsed++]
    if (height === 0 || parentOfMatch === 0) {
      const hash = data.hashes[hashUsed++]
      if (height === 0 && parentOfMatch) {
        hashes.push(hash)
      }

      return hash
    }

    const left = extract(height - 1, pos * 2)
    if (pos * 2 + 1 < calcTreeWidth(data.numTransactions, height - 1)) {
      const right = extract(height - 1, pos * 2 + 1)
      if (left.equals(right)) {
        throw new Error('Merkle child hashes are equivalent (' +
          left.toString('hex') + ')')
      }

      return hash256(left, right)
    }

    return hash256(left, left)
  }

  const merkleRoot = extract(Math.ceil(Math.log2(data.numTransactions)), 0)

  const flagByte = Math.floor(bitsUsed / 8)
  if (flagByte + 1 < data.flags.length ||
      data.flags[flagByte] > (1 << bitsUsed % 8)) {
    throw new Error('Tree did not consume all flag bits')
  }

  if (hashUsed !== data.hashes.length) {
    throw new Error('Tree did not consume all hashes')
  }

  if (!merkleRoot.equals(data.merkleRoot)) {
    throw new Error('Calculated Merkle root does not match header, calculated: ' +
      merkleRoot.toString('hex') + ', header: ' + data.merkleRoot.toString('hex'))
  }

  return hashes
}

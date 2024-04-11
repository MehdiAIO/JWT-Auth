const crypto = require('crypto');
const randomHexString = crypto.randomBytes(64).toString('hex');
console.log(randomHexString);

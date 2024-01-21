const crypto = require('crypto');

let shuffle = (inArr, seed, unshuffle = false) => {

    let outArr = Array.from(inArr),
        len = inArr.length

    let swap = (a, b) => [outArr[a], outArr[b]] = [outArr[b], outArr[a]]

    for (
            var i = unshuffle ? len - 1 : 0;
            unshuffle && i >= 0 || !unshuffle && i < len;
            i += unshuffle ? -1 : 1
        )

        swap(seed[i % seed.length] % len, i)

    return outArr;

}

const generateKeyPairPEM = () => {
    const keyPair = crypto.getDiffieHellman('modp18');
    keyPair.generateKeys();
    return {
        privateKey: keyPair.getPrivateKey('hex'),
        publicKey: keyPair.getPublicKey('hex'),
        diff: keyPair
    };
}

const generateKeyPairPEMFromPrivateKey = (privatePrime) => {
    const privateKey = privatePrime.split(':')[0];
    const prime = privatePrime.split(':')[1];

    const keyPair = crypto.createDiffieHellman(prime, 'hex');
    keyPair.setPrivateKey(privateKey, 'hex');
    keyPair.generateKeys();
    return {
        privateKey: keyPair.getPrivateKey('hex'),
        publicKey: keyPair.getPublicKey('hex'),
        diff: keyPair
    };
}

const generateSharedKey = (bob, alicePublic) => {
    alicePublic = Buffer.from(alicePublic, 'hex');
    return bob.computeSecret(alicePublic, null, 'hex');
}

const encrypt = (data, sharedKey) => {
    const iv = crypto.randomBytes(16);
    const derivedKey = crypto.createHash('sha256').update(sharedKey).digest('base64');
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(derivedKey, 'base64'), iv);

    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const json = JSON.stringify({ encrypted, iv: iv.toString('hex') });
    const buffer = Buffer.from(json, 'utf8');
    const hex = buffer.toString('hex');
    const list = hex.split('');
    const shuffleSeed = sharedKey.match(/\d+/g).map(str => parseInt(str))
    const shuffled = shuffle(list, shuffleSeed);

    return shuffled.join('');
};

const decrypt = (encryptedData, sharedKey) => {
    const shuffleSeed = sharedKey.match(/\d+/g).map(str => parseInt(str))
    const unshuffled = shuffle(encryptedData.split(''), shuffleSeed, true);
    const hex = unshuffled.join('');
    const buffer = Buffer.from(hex, 'hex');
    const json = JSON.parse(buffer.toString('utf8'));

    encryptedData = json;

    const iv = Buffer.from(encryptedData.iv, 'hex');
    const derivedKey = crypto.createHash('sha256').update(sharedKey).digest('base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(derivedKey, 'base64'), iv);

    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
};

const hash = (data) => {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}

module.exports = {
    generateKeyPairPEMFromPrivateKey,
    generateKeyPairPEM,
    generateSharedKey,
    encrypt,
    decrypt,
    hash
};
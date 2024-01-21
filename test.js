const enc = require('./lib/encryption');
const toEncrypt = 'Hello World!';

for (let i = 1; i < 0; i++) {

    const bob = enc.generateKeyPairPEM('SecurePassword', 'SecureSalt');
    const alice = enc.generateKeyPairPEM('SecurePassword', 'SecureSalt');

    const bobSharedKey = enc.generateSharedKey(bob.diff, alice.publicKey);
    const aliceSharedKey = enc.generateSharedKey(alice.diff, bob.publicKey);

    const encrypted = enc.encrypt(toEncrypt, bobSharedKey);
    const decrypted = enc.decrypt(encrypted, aliceSharedKey);

    console.log(bob.publicKey.length)
    
    console.log(i, decrypted === toEncrypt);
    if (!decrypted === toEncrypt) throw new Error('Decryption failed!');

}

console.log(Buffer.from('localhost:1028').toString('hex'))
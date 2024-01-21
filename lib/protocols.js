const encryption = require('./encryption');

const keyExchange = (message) => {
    const publicKey = message.split(':')[1];
    return publicKey;
}


module.exports = {
    keyExchange
}
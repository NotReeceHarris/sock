const exchange = (message) => {
    // Shema: exchange:publicKey

    if (!message.includes('exchange:')) {
        return false;
    }

    const publicKey = message.split(':')[1];

    if (!publicKey || publicKey.length != 2048) {
        return false;
    }

    return publicKey;
};

module.exports = {
    exchange
};
const crypto = require('crypto');

const parseYellowBook = (yellowBookContents) => {
    // line schema: id:hex(name):hash(sharedSecret):hex(address)

    let yellowBookContacts = {};

    yellowBookContents.split('\n').forEach((line) => {

        if (line.length === 0) return;

        const id = line.split(':')[0];
        const name = Buffer.from(line.split(':')[1], 'hex').toString('utf8');
        const hash = line.split(':')[2];
        const address = Buffer.from(line.split(':')[3].replace('\r', ''), 'hex').toString('utf8');

        yellowBookContacts[id] = {
            name,
            hash,
            address
        };
    });

    return yellowBookContacts;
}

module.exports = {
    parseYellowBook
}
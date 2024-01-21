const prompts = require('prompts');
const WebSocket = require('ws');
const fs = require('fs');

const protocols = require('./lib/protocols');
const encryption = require('./lib/encryption');
const validation = require('./lib/validation');
const parser = require('./lib/parser');

let keyFile = './private.sock.key';
let yellowBook = './yellowbook.sock.txt';
let port = 8080;

new Promise((res) => {

    if (process.argv.includes('--key')) {
        const key = process.argv[process.argv.indexOf('--key') + 1];
        keyFile = key;
    } else {
        console.log(`[Sock] No keyfile (--key) provided, using "${keyFile}"`);
    }

    if (!fs.existsSync(keyFile)) {
        console.log('[Sock] No keyfile found, Generating private key...');

        const keyPair = encryption.generateKeyPairPEM();
        fs.writeFileSync(keyFile, keyPair.privateKey + ':' + keyPair.diff.getPrime('hex'));

        res(keyPair);
    } else {
        console.log('[Sock] Keyfile found, using existing private key...');

        const keyContents = fs.readFileSync(keyFile, 'utf8');
        const keyPair = encryption.generateKeyPairPEMFromPrivateKey(keyContents);

        res(keyPair);
    }

    
}).then((keyPair) => {

    if (process.argv.includes('--yellowbook')) {
        const book = process.argv[process.argv.indexOf('--yellowbook') + 1];
        yellowBook = book;

        if (!fs.existsSync(yellowBook)) {
            console.log('[Sock] No Yellow Book found, Generating Yellow Book...');
            fs.writeFileSync(yellowBook, '');
        }

    } else {
        console.log(`[Sock] No Yellow Book (--yellowbook) provided, using "${yellowBook}"`);

        if (!fs.existsSync(yellowBook)) {
            console.log('[Sock] No Yellow Book found, Generating Yellow Book...');
            fs.writeFileSync(yellowBook, '');
        } else {
            console.log('[Sock] Yellow Book found, using existing Yellow Book...');
        }
    }

    const yellowBookContents = fs.readFileSync(yellowBook, 'utf8');
    const yellowBookContacts = parser.parseYellowBook(yellowBookContents);

    new Promise(async (res) => {

        let contact;

        if (Object.keys(yellowBookContacts).length !== 0) {

            const formattedContacts = [
                {
                    title: 'Add new connection',
                    description: 'Add a new connection',
                    value: 'add'
                },
                ...Object.keys(yellowBookContacts).map((id) => {
                    const contact = yellowBookContacts[id];
                    return {
                        title: contact.name,
                        value: id,
                        description: contact.hash
                    }
                })
            ]

            const response = await prompts({
                type: 'select',
                name: 'contact',
                message: 'Yellow Book (Contacts)',
                choices: formattedContacts
            });

            if (response.contact !== 'add') {
                contact = yellowBookContacts[response.contact]
            }

        }

        if (!contact) {
            const response = await prompts([
                {
                    type: 'text',
                    name: 'address',
                    message: 'Address of Alice (IP:Port)'
                }
            ]);

            const address = response.address;

            const response2 = await prompts([
                {
                    type: 'confirm',
                    name: 'confirmed',
                    message: 'Do you want to save this as a contact?'
                }
            ]);

            if (response2.confirmed) {
                const response3 = await prompts([
                    {
                        type: 'text',
                        name: 'name',
                        message: 'Name of contact'
                    }
                ]);

                const name = response3.name;
                const id = yellowBookContents.split('\n').length;

                fs.appendFileSync(yellowBook, `${id}:${Buffer.from(name).toString('hex')}:waitingOnConnection:${Buffer.from(address).toString('hex')}\n`);

                contact = {
                    name,
                    hash: 'waitingOnConnection',
                    address
                }
            
            } else {
                contact = {
                    name: 'Alice',
                    hash: 'notSaved',
                    address
                }
            }

        }

        res(contact);

    }).then((contact) => {

        if (process.argv.includes('--port')) {
            const p = process.argv[process.argv.indexOf('--port') + 1];
            port = p;
        } else {
            console.log(`[Sock] No port (--port) provided, using "${port}"`);
        }

        startConnection(contact);

        function startConnection (contact, retry = false) {

            const server = new WebSocket.Server({ port });
            const client = new WebSocket(`ws://${contact.address}`);

            let clientConnected = false;
            let serverConnected = false;
            let exchangeHappened = false;

            let intervalId;

            intervalId = setInterval(() => {
                if (clientConnected && serverConnected && exchangeHappened) {
                    console.log('[Sock] Exchange with', contact.name, 'successful');
                    console.log('[Sock] Shared key:', contact.hash, '\n')
                    console.log('-----=====[ Encrypted Chat ]=====-----\n')
                    clearInterval(intervalId);
                }
            }, 500);


            if (!retry) {
                console.log(`[Sock] Connecting to "${contact.name}" on (${contact.address})...`);
            }

            client.on('open', () => {

                if (serverConnected) {
                    console.log('[Sock] Connection already established, closing connection...');
                    return client.close();
                } else {
                    serverConnected = true;
                }
                
                console.log('[Sock] We have connected to', contact.name, '.');
                console.log('[Sock] Sending key exchange...');
                client.send(`exchange:${keyPair.publicKey}`);
            });

            client.on('error', (err) => {
                if (err.code === 'ECONNREFUSED') {
                    setTimeout(() => {
                        server.close();
                        client.close();
                        startConnection(contact, true);
                    }, 1000);
                }
            })

            server.on('connection', function connection(ws) {

                if (clientConnected) {
                    console.log('[Sock] Connection already established, closing connection...');
                    return ws.close();
                } else {
                    console.log('[Sock]', contact.name, 'connected to us.');
                    clientConnected = true;
                }

                ws.on('message', (data) => {

                    data = data.toString();

                    console.log('mes:', data)

                    if (!exchangeHappened) {
                        if (!validation.exchange(data)) {
                            console.log('[Sock] Exchange attempt from', ws._socket.remoteAddress, 'rejected, invalid exchange message. Closing connection...');
                            return ws.close();
                        }

                        const publicKey = protocols.keyExchange(data);
                        const sharedKey = encryption.generateSharedKey(keyPair.diff, publicKey);

                        contact.hash = encryption.hash(sharedKey);
                        contact.sharedKey = sharedKey;
                        exchangeHappened = true;

                    } else {
                        const decrypted = encryption.decrypt(data, contact.sharedKey);
                        console.log(`[${contact.name}]:`, decrypted);
                    }

                });
            })

            server.on('listening', function() {
                if (!retry) {
                    console.log(`[Sock] Waiting for "${contact.name}" to connect on (${contact.address})...`);
                }
            });

        }
    });

});
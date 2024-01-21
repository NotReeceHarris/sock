

wss.on
        
wss.on('connection', function connection(ws) {

    if (client) {
        console.log('[Connection] Connection attempt from', ws._socket.remoteAddress, 'rejected, already connected to', client._socket.remoteAddress);
        return ws.close();
    } else {
        client = {
            ws,
            exchangeHappened: false
        }
        
        console.log('Con')

        ws.send(`exchange:${keyPair.publicKey}`);
    }

    ws.on('message', function message(data) {

        if (client.ws !== ws) {
            console.log('[Connection] Something weird is happening, registered client is not the same as the sender of the message. Closing connection...');
            return ws.close();
        }
        
        if (!client.exchangeHappened) {
            if (!validation.exchange(message)) {
                console.log('[Connection] Exchange attempt from', ws._socket.remoteAddress, 'rejected, invalid exchange message. Closing connection...');
                return ws.close();
            }

            if (!client.exchangeHappened) {
                const publicKey = protocols.exchange(ws, message);
                const sharedKey = encryption.generateSharedKey(keyPair.diff, publicKey);

                client.publicKey = publicKey;
                client.sharedKey = sharedKey;
                client.exchangeHappened = true;

                console.log('[Connection] Exchange with', ws._socket.remoteAddress, 'successful');
                console.log('[Connection] Shared key:', sharedKey, '\n')
                console.log('-----=====[ Encrypted Chat ]=====-----\n')

            } else {
                console.log('[Connection] Exchange attempt from', ws._socket.remoteAddress, 'rejected, already exchanged with', client._socket.remoteAddress, '. Closing connection...');
                return ws.close();
            }
        }

        const message = Buffer.from(data, 'hex').toString('utf8');
        const decrypted = encryption.decrypt(message, client.sharedKey);

        console.log(`[${contact.name}]:`, decrypted);
    });

    ws.on('close', function close() {
        
        if (client.ws === ws) {
            console.log(`[Connection] Connection to "${contact.name}" closed`)
            client = null;
        }

    });

});  

wss.on('listening', function() {
    console.log('[Sock] listening on port', port);
});

wss.on('error', function(err) {
    
    if (err.code === 'EADDRINUSE') {
        console.log('[Sock] Port', port, 'is already in use, trying port', port + 1);
        return;
    }

    if (err.code === 'ECONNREFUSED') {
        console.log(`[Sock] Connection to "${contact.name}" refused, retrying in 5 seconds...`);

        setTimeout(() => {
            startConnection(contact, host);
        }, 5000);
        return;
    }

    console.log('[Sock] Error:', err.code);
});
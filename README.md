# node-signal-client

This is a client library for Signal, the secure messenger app by Open Whisper Systems.

It works by means of a dirty port of the [Signal Chrome App](https://github.com/WhisperSystems/Signal-Desktop) to Node.js, which serves as the client. This is cloned during the `npm install` process. Despite being designed for Chrome, the environment is appropriately patched to allow the program to run in Node.js, unhindered.

# Warning

When you `require` this library, a bunch of things happen on the global scope! In order to port the Chrome app, this had to be done -- just be aware of this in case your application also deals with globals. If so, you'll probably want to communicate with it through IPC or something instead of `require`ing it directly.

## install

`npm install signal-client`

Try it out by executing `node run.js`

## usage

The following is copied from the example `run.js`

```javascript
const SignalClient = require('signal-client');

const client = new SignalClient("nodejs");

// triggered when you receive a message on signal
client.on('message', (ev) => {
  console.log('received message from', ev.data.source, ev.data);
});

// triggered when a sent message synced from another client
client.on('sent', (ev) => {
  console.log('sent a message to', ev.data.destination, ev.data);
});

client.on('receipt', (ev)=>{
  var pushMessage = ev.proto;
  var timestamp = pushMessage.timestamp.toNumber();
  console.log(
    'delivery receipt from',
    pushMessage.source + '.' + pushMessage.sourceDevice,
    timestamp
  );
});


client.on('contact', (ev)=>{
  console.log('contact received', ev.contactDetails);
});

client.on('group', (ev)=>{
  console.log('group received', ev.groupDetails);
});

client.on('read', (ev)=>{
  var read_at   = ev.timestamp;
  var timestamp = ev.read.timestamp;
  var sender    = ev.read.sender;
  console.log('read receipt', sender, timestamp);
});

client.on('error', (ev)=>{
  console.log('error', ev.error, ev.error.stack);
});

client.start();
```

## storage

The client stores keys and other information in two places.

Two sqlite databases, and a data/ directory are created in the current working directory.

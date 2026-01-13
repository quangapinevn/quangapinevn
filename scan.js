#!/usr/bin/env node
const { spawn, exec } = require('child_process');
const fs = require('fs');
const http = require('http');
const SCAN_DURATION = 180;
const PORT_INTERVAL = 30;
const ROUND_INTERVAL = 3600;
const BANDWIDTH = "10G";
const OUTPUT_FILE = "output.txt";
const TEMP_FILE = "all_proxies.txt";
const HTTP_ = 16032;
const ANSI_REGEX = /\x1B\[[0-?]*[ -/]*[@-~]/g;
let lastUpdateTime = new Date();
const s = [];
for (let base = 1; base <= 9; base++) {
    for (let offset = 0; offset <= 10; offset++) {
        s.push(base * 1000 + offset);
    }
}
for (let offset = 1; offset <= 9; offset++) {
    s.push(10000 + offset);
}
for (let base = 2; base <= 9; base++) {
    for (let offset = 0; offset <= 10; offset++) {
        s.push(base * 10000 + offset);
    }
}
console.log(`[INFO] Total s to scan: ${ports.length}`);
let currentPort = null;
let nextPort = 3128; // Thay nextRoundPort thành nextPort để rõ nghĩa: port tiếp theo sẽ scan
function stripAnsiCodes(str) {
    return str.replace(ANSI_REGEX, '');
}
function clearFile(filename) {
    fs.writeFileSync(filename, '');
}
function formatDateTime(date) {
    const vnTime = new Date(date.toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh' }));
    const hours = String(vnTime.getHours()).padStart(2, '0');
    const minutes = String(vnTime.getMinutes()).padStart(2, '0');
    const seconds = String(vnTime.getSeconds()).padStart(2, '0');
    const day = String(vnTime.getDate()).padStart(2, '0');
    const month = String(vnTime.getMonth() + 1).padStart(2, '0');
    const year = vnTime.getFullYear();
    return `${hours}:${minutes}:${seconds} ${day}/${month}/${year}`;
}
function getProxyCount() {
    if (!fs.existsSync(TEMP_FILE)) {
        return 0;
    }
    const content = fs.readFileSync(TEMP_FILE, 'utf8').trim();
    if (!content) return 0;
    const proxies = content.split('\n').filter(Boolean);
    return new Set(proxies).size;
}
function runScan(port) {
    return new Promise((resolve) => {
        clearFile(OUTPUT_FILE);
        console.log(`[INFO] Scanning port ${port}...`);
        currentPort = port;
        const command = `zmap -w all.txt -p ${port} -q -B${BANDWIDTH} -T5 -i eth0 --cooldown-time 1 | ./prox -p ${port}`;
       
        const process = spawn('sh', ['-c', command]);
       
        let scanActive = true;
        let consecutiveZeroHttp = 0;
        let lastZeroThreadTime = 0;
        const ZERO_THREAD_COOLDOWN = 2000;
        const cleanup = async (reason) => {
            if (!scanActive) return;
            scanActive = false;
            console.log(`[INFO] Cleanup initiated for port ${port}: ${reason}`);
            process.stdout.removeAllListeners();
            process.stderr.removeAllListeners();
            process.removeAllListeners();
           
            try {
                process.kill('SIGTERM');
                await sleep(500);
                try { process.kill('SIGKILL'); } catch (e) {}
            } catch (e) {}
           
            console.log(`[INFO] Killing all zmap and prox processes for port ${port}...`);
            await new Promise((resolve) => {
                exec(`pkill -9 -f "zmap.*-p ${port}"`, () => {
                    exec(`pkill -9 -f "prox.*-p ${port}"`, () => resolve());
                });
            });
           
            await sleep(1000);
            console.log(`[INFO] All processes for port ${port} cleaned up`);
           
            resolve(reason === 'early_stop');
        };
        process.stdout.on('data', async (data) => {
            if (!scanActive) return;
           
            const lines = data.toString().split('\n');
            for (const line of lines) {
                if (!scanActive) return;
               
                if (line.trim()) {
                    const cleanLine = stripAnsiCodes(line).trim();
                    console.log(`[DEBUG] Port ${port} Output: ${cleanLine}`);
                   
                    if (cleanLine.toLowerCase().includes('new proxy')) {
                        const proxyMatch = cleanLine.match(/new proxy\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+)/i);
                        if (proxyMatch) {
                            const proxy = proxyMatch[1];
                            console.log(`[INFO] Found proxy: ${proxy} - Writing to file immediately`);
                            fs.appendFileSync(OUTPUT_FILE, proxy + '\n');
                            fs.appendFileSync(TEMP_FILE, proxy + '\n');
                            lastUpdateTime = new Date();
                        }
                    }
                   
                    const now = Date.now();
                    if (cleanLine.toLowerCase().includes('with 0 open http threads')) {
                        if (now - lastZeroThreadTime > ZERO_THREAD_COOLDOWN) {
                            consecutiveZeroHttp++;
                            lastZeroThreadTime = now;
                            console.log(`[DEBUG] Port ${port} - Detected zero threads: count=${consecutiveZeroHttp}`);
                           
                            if (consecutiveZeroHttp >= 3) {
                                console.log(`[INFO] Early stop for port ${port} - no active threads (detected ${consecutiveZeroHttp} times)`);
                                await cleanup('early_stop');
                                return;
                            }
                        }
                    } else if (cleanLine.toLowerCase().includes('open http threads')) {
                        consecutiveZeroHttp = 0;
                    }
                }
            }
        });
        process.stderr.on('data', (data) => {
            if (!scanActive) return;
            const errorMsg = data.toString().trim();
            if (errorMsg) {
                console.log(`[STDERR] Port ${port}: ${errorMsg}`);
            }
        });
        process.on('close', (code, signal) => {
            if (scanActive) {
                console.log(`[INFO] Port ${port} process closed (code: ${code}, signal: ${signal})`);
                cleanup('process_closed').catch(() => {});
            }
        });
        process.on('error', (err) => {
            if (scanActive) {
                console.log(`[ERROR] Port ${port} process error: ${err.message}`);
                cleanup('process_error').catch(() => {});
            }
        });
        const timeout = setTimeout(() => {
            if (scanActive) {
                console.log(`[INFO] Timeout for port ${port}`);
                cleanup('timeout').catch(() => {});
            }
        }, SCAN_DURATION * 1000);
        process.on('exit', () => clearTimeout(timeout));
    });
}
function processResults(port) {
    if (!fs.existsSync(OUTPUT_FILE)) {
        console.log(`[WARN] File ${OUTPUT_FILE} not found for port ${port}`);
        return;
    }
    const content = fs.readFileSync(OUTPUT_FILE, 'utf8').trim();
   
    if (!content) {
        console.log(`[INFO] No proxies found on port ${port}`);
        return;
    }
    const proxies = content.split('\n').filter(Boolean);
    console.log(`[INFO] Total proxies from port ${port}: ${proxies.length}`);
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
function startHttpServer() {
    const server = http.createServer((req, res) => {
        if (req.url === '/vn' || req.url === '/vn/') {
            if (fs.existsSync(TEMP_FILE)) {
                const content = fs.readFileSync(TEMP_FILE, 'utf8').trim();
                res.writeHead(200, {
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Content-Disposition': 'inline'
                });
                res.end(content);
            } else {
                res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end('No proxies available yet');
            }
        } else if (req.url === '/status' || req.url === '/status/') {
            const proxyCount = getProxyCount();
            const lastUpdate = formatDateTime(lastUpdateTime);
            let roundStatus;
            if (currentPort !== null) {
                // Đang scan port hiện tại → hiển thị port đang scan
                roundStatus = currentPort.toString();
            } else if (nextPort !== null) {
                // Không đang scan (chờ giữa các port hoặc chờ round mới) → hiển thị port sắp tới
                roundStatus = nextPort.toString();
            } else {
                roundStatus = "Idle";
            }
            const status = `VietNam Proxy API Status:
Total Proxies: ${proxyCount} | Last updated: ${lastUpdate} | Round: ${roundStatus}`;
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(status);
        } else if (req.url === '/') {
            const homePage = `Info: VietNam Proxy API by @no_sangvings and @quangapi
Available commands:
/vn - View the proxy list
/status - Check the proxy scan progress`;
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(homePage);
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Not found');
        }
    });
    server.listen(HTTP_PORT, '0.0.0.0', () => {
        console.log(`[INFO] HTTP Server running on port ${HTTP_PORT}`);
        console.log(`[INFO] Access proxies at: http://0.0.0.0:${HTTP_PORT}/vn`);
        console.log(`[INFO] Check status at: http://0.0.0.0:${HTTP_PORT}/status`);
    });
    return server;
}
async function main() {
    console.log("[INFO] Starting proxy scanner. Press Ctrl+C to stop.");
   
    const server = startHttpServer();
   
    let scanRound = 1;
    try {
        while (true) {
            console.log(`\n[INFO] Starting scan round ${scanRound}`);
            console.log("[INFO] " + "=".repeat(50));
            clearFile(TEMP_FILE);
            currentPort = null;
            nextPort = ports.length > 0 ? ports[0] : null;
            for (let i = 0; i < ports.length; i++) {
                const port = ports[i];
                console.log(`\n[INFO] === Scanning port ${port} (${i + 1}/${ports.length}) ===`);
               
                await runScan(port);
                console.log(`[INFO] Final cleanup for port ${port}...`);
                await new Promise((resolve) => {
                    exec(`pkill -9 -f "zmap.*-p ${port}"`, () => {
                        exec(`pkill -9 -f "prox.*-p ${port}"`, () => {
                            exec('pkill -9 -f zmap', () => {
                                exec('pkill -9 -f prox', () => resolve());
                            });
                        });
                    });
                });
               
                console.log(`[INFO] Waiting for all processes to terminate...`);
                await sleep(2000);
               
                processResults(port);
                const currentProxyCount = getProxyCount();
                console.log(`[INFO] Current total proxy count: ${currentProxyCount}`);
                console.log(`[INFO] === Port ${port} scan completed ===\n`);
               
                // Cập nhật nextPort cho trạng thái chờ port tiếp theo
                if (i < ports.length - 1) {
                    nextPort = ports[i + 1];
                } else {
                    nextPort = null; // Sau port cuối cùng trong round
                }
               
                if (i < ports.length - 1) {
                    console.log(`[INFO] Waiting ${PORT_INTERVAL} seconds before next port...`);
                    await sleep(PORT_INTERVAL * 1000);
                }
            }
            console.log(`\n[INFO] Completed scan round ${scanRound}`);
            scanRound++;
            currentPort = null;
            nextPort = ports.length > 0 ? ports[0] : null;
            console.log(`[INFO] Next scan round in ${ROUND_INTERVAL / 60} minutes`);
            console.log("[INFO] " + "=".repeat(50) + "\n");
            await sleep(ROUND_INTERVAL * 1000);
        }
    } catch (error) {
        console.error("[ERROR]", error);
        server.close();
        process.exit(1);
    }
}
process.on('SIGINT', () => {
    console.log("\n[INFO] Stopping scanner...");
    exec('pkill -f zmap', () => {});
    exec('pkill -f prox', () => {});
    process.exit(0);
});
process.on('SIGTSTP', () => {
    console.log("\n[INFO] Stopping scanner...");
    exec('pkill -f zmap', () => {});
    exec('pkill -f prox', () => {});
    process.exit(0);
});
if (require.main === module) {
    main();
}

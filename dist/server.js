"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const tls = __importStar(require("tls"));
const crypto = __importStar(require("crypto"));
const https = __importStar(require("https"));
const dns = __importStar(require("dns"));
const ws_1 = __importDefault(require("ws"));
class ProxyDetector {
    constructor() {
        this.blockedIPs = new Set();
        this.blockedIPsData = [];
        this.blocklistDomains = new Set();
    }
    async initializeBlocklist() {
        try {
            const response = await new Promise((resolve, reject) => {
                https.get('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', (res) => {
                    let data = '';
                    res.on('data', (chunk) => data += chunk);
                    res.on('end', () => resolve(data));
                }).on('error', reject);
            });
            const lines = response.split('\n');
            for (const line of lines) {
                if (line.startsWith('0.0.0.0') || line.startsWith('127.0.0.1')) {
                    const parts = line.split(/\s+/);
                    if (parts.length >= 2) {
                        const domain = parts[1];
                        if (domain && !domain.startsWith('#') && domain.includes('.')) {
                            const cleanDomain = domain.replace(/^#|\s*#.*$/, '').trim();
                            if (cleanDomain && cleanDomain.includes('.')) {
                                this.blocklistDomains.add(cleanDomain.toLowerCase());
                            }
                        }
                    }
                }
            }
            console.log(`Loaded ${this.blocklistDomains.size} domains from blocklist`);
        }
        catch (error) {
            console.log('Failed to load blocklist, using behavioral detection only');
        }
    }
    async getDomainIP(domain) {
        return new Promise((resolve, reject) => {
            dns.lookup(domain, (err, address) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(address);
                }
            });
        });
    }
    isIPBlocked(ip) {
        return this.blockedIPs.has(ip);
    }
    blockIP(ip, domain) {
        if (!this.blockedIPs.has(ip)) {
            this.blockedIPs.add(ip);
            this.blockedIPsData.push({
                ip,
                domain,
                timestamp: Date.now()
            });
        }
    }
    getBlockedIPs() {
        return this.blockedIPsData;
    }
    async getTLSFingerprint(domain) {
        return new Promise((resolve, reject) => {
            const socket = tls.connect(443, domain, { servername: domain });
            const startTime = process.hrtime.bigint();
            socket.on('secureConnect', () => {
                const cert = socket.getPeerCertificate();
                const fingerprint = crypto.createHash('sha256').update(cert.raw).digest('hex');
                const endTime = process.hrtime.bigint();
                socket.destroy();
                resolve(fingerprint);
            });
            socket.on('error', (err) => {
                reject(err);
            });
            socket.setTimeout(5000, () => {
                socket.destroy();
                reject(new Error('TLS handshake timeout'));
            });
        });
    }
    async measureHandshakeTime(domain) {
        return new Promise((resolve, reject) => {
            const startTime = process.hrtime.bigint();
            const socket = tls.connect(443, domain, { servername: domain });
            socket.on('secureConnect', () => {
                const endTime = process.hrtime.bigint();
                const handshakeTime = Number(endTime - startTime) / 1000000;
                socket.destroy();
                resolve(handshakeTime);
            });
            socket.on('error', () => {
                reject(new Error('Handshake failed'));
            });
            socket.setTimeout(5000, () => {
                socket.destroy();
                reject(new Error('Handshake timeout'));
            });
        });
    }
    async makeHTTPSRequest(domain) {
        return new Promise((resolve, reject) => {
            const startTime = process.hrtime.bigint();
            const req = https.request({
                hostname: domain,
                port: 443,
                path: '/',
                method: 'GET',
                headers: { 'User-Agent': 'Mozilla/5.0' }
            }, (res) => {
                let body = '';
                res.on('data', (chunk) => {
                    body += chunk;
                });
                res.on('end', () => {
                    const endTime = process.hrtime.bigint();
                    const latency = Number(endTime - startTime) / 1000000;
                    resolve({
                        headers: res.headers,
                        body: body,
                        latency: latency
                    });
                });
            });
            req.on('error', (err) => reject);
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            req.end();
        });
    }
    async checkBareMux(domain) {
        try {
            const response = await this.makeHTTPSRequest(domain);
            const body = response.body.toLowerCase();
            const proxyIndicators = [
                'proxy server',
                'tunnel connection',
                'socket forward',
                'http tunnel',
                'websocket proxy'
            ];
            return proxyIndicators.some(indicator => body.includes(indicator));
        }
        catch (error) {
            return false;
        }
    }
    async checkWispServerConnection(domain) {
        try {
            const response = await this.makeHTTPSRequest(domain);
            const body = response.body.toLowerCase();
            const explicitProxyPatterns = [
                'tunnel websocket',
                'proxy websocket',
                'websocket tunnel',
                'socket proxy',
                'wisp server',
                'multiplexed websocket',
                'websocket multiplexing',
                'proxy tunnel',
                'tunnel server'
            ];
            const hasExplicitProxy = explicitProxyPatterns.some(pattern => body.includes(pattern));
            if (hasExplicitProxy) {
                const wsUrls = body.match(/wss?:\/\/[^\s"']+/g);
                if (wsUrls && wsUrls.length > 0) {
                    let externalWispConnections = 0;
                    for (const wsUrl of wsUrls) {
                        try {
                            const wsDomain = wsUrl.replace(/^(wss?:\/\/)/, '').split('/')[0].split(':')[0];
                            if (wsDomain !== domain && await this.testWebSocketUpgrade(wsDomain)) {
                                externalWispConnections++;
                            }
                        }
                        catch (error) {
                            continue;
                        }
                    }
                    return externalWispConnections >= 2;
                }
            }
            return false;
        }
        catch (error) {
            return false;
        }
    }
    calculateHeaderEntropy(headers) {
        const headerValues = Object.values(headers).filter(val => val !== undefined);
        const headerString = headerValues.join('');
        const frequency = {};
        for (const char of headerString) {
            frequency[char] = (frequency[char] || 0) + 1;
        }
        let entropy = 0;
        const length = headerString.length;
        for (const char in frequency) {
            const probability = frequency[char] / length;
            entropy -= probability * Math.log2(probability);
        }
        return entropy;
    }
    calculateVariance(values) {
        const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
        const squaredDiffs = values.map(val => Math.pow(val - mean, 2));
        return squaredDiffs.reduce((sum, val) => sum + val, 0) / values.length;
    }
    async testWebSocketUpgrade(domain) {
        return new Promise((resolve) => {
            const wsUrl = `wss://${domain}`;
            const ws = new ws_1.default(wsUrl, {
                headers: { 'User-Agent': 'Mozilla/5.0' }
            });
            const timeout = setTimeout(() => {
                ws.terminate();
                resolve(false);
            }, 5000);
            ws.on('open', () => {
                clearTimeout(timeout);
                ws.close();
                resolve(true);
            });
            ws.on('error', () => {
                clearTimeout(timeout);
                resolve(false);
            });
        });
    }
    async analyzeDomain(domain) {
        const domainLower = domain.toLowerCase();
        if (this.blocklistDomains.has(domainLower)) {
            try {
                const ip = await this.getDomainIP(domain);
                this.blockIP(ip, domain);
                return {
                    domain,
                    blocked: true,
                    ip
                };
            }
            catch (error) {
                return {
                    domain,
                    blocked: true
                };
            }
        }
        const numRequests = 5;
        const tlsFingerprints = [];
        const handshakeTimes = [];
        const latencies = [];
        const responseHashes = [];
        const headerEntropies = [];
        for (let i = 0; i < numRequests; i++) {
            try {
                const fingerprint = await this.getTLSFingerprint(domain);
                tlsFingerprints.push(fingerprint);
                const handshakeTime = await this.measureHandshakeTime(domain);
                handshakeTimes.push(handshakeTime);
                const response = await this.makeHTTPSRequest(domain);
                latencies.push(response.latency);
                const responseHash = crypto.createHash('sha256').update(response.body).digest('hex');
                responseHashes.push(responseHash);
                const entropy = this.calculateHeaderEntropy(response.headers);
                headerEntropies.push(entropy);
            }
            catch (error) {
                continue;
            }
        }
        const uniqueFingerprints = new Set(tlsFingerprints).size;
        const uniqueResponseHashes = new Set(responseHashes).size;
        const avgHeaderEntropy = headerEntropies.reduce((sum, val) => sum + val, 0) / headerEntropies.length || 0;
        const latencyStats = {
            min: Math.min(...latencies),
            max: Math.max(...latencies),
            avg: latencies.reduce((sum, val) => sum + val, 0) / latencies.length || 0,
            variance: this.calculateVariance(latencies)
        };
        const handshakeVariance = this.calculateVariance(handshakeTimes);
        const websocketUpgrade = await this.testWebSocketUpgrade(domain);
        const isBareMux = await this.checkBareMux(domain);
        const hasWispConnection = await this.checkWispServerConnection(domain);
        let anomalyScore = 0;
        if (uniqueFingerprints > 1) {
            anomalyScore += uniqueFingerprints * 0.4;
        }
        if (handshakeVariance > 100) {
            anomalyScore += Math.min(handshakeVariance / 100, 1) * 0.3;
        }
        if (latencyStats.variance > 1000) {
            anomalyScore += Math.min(latencyStats.variance / 1000, 1) * 0.2;
        }
        if (uniqueResponseHashes > 3) {
            anomalyScore += (uniqueResponseHashes - 3) * 0.15;
        }
        if (!websocketUpgrade) {
            anomalyScore += 0.1;
        }
        if (isBareMux) {
            anomalyScore += 0.5;
        }
        if (hasWispConnection) {
            anomalyScore += 0.6;
        }
        const proxyLikely = anomalyScore > 0.9;
        let ip;
        if (proxyLikely) {
            try {
                ip = await this.getDomainIP(domain);
                this.blockIP(ip, domain);
            }
            catch (error) {
                return {
                    domain,
                    blocked: false
                };
            }
        }
        return {
            domain,
            blocked: proxyLikely,
            ip
        };
    }
}
const app = (0, express_1.default)();
const detector = new ProxyDetector();
const PORT = process.env.PORT || 3000;
app.get('/v1/dusk/check/url=:domain', async (req, res) => {
    try {
        let domain = req.params.domain.replace(/"/g, '');
        if (domain.includes('/')) {
            domain = domain.split('/')[0];
        }
        if (!domain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
            return res.status(400).json({ error: 'Invalid domain format' });
        }
        const result = await detector.analyzeDomain(domain);
        res.json(result);
    }
    catch (error) {
        res.status(500).json({ error: 'Analysis failed' });
    }
});
app.get('/v1/dusk/blocked-ips', (req, res) => {
    try {
        const blockedIPs = detector.getBlockedIPs();
        res.json(blockedIPs);
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to get blocked IPs' });
    }
});
async function startServer() {
    try {
        await detector.initializeBlocklist();
    }
    catch (error) {
        console.log('Failed to initialize blocklist, using behavioral detection only');
    }
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}
startServer();
exports.default = app;
//# sourceMappingURL=server.js.map
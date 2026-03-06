import express, { Request, Response } from 'express';
import * as tls from 'tls';
import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import WebSocket from 'ws';

interface LatencyStats {
  min: number;
  max: number;
  avg: number;
  variance: number;
}

interface ProxyDetectionResult {
  domain: string;
  tlsFingerprints: string[];
  handshakeTimes: number[];
  latencyStats: LatencyStats;
  headerEntropy: number;
  responseHashConsistency: boolean;
  websocketUpgrade: boolean;
  anomalyScore: number;
  proxyLikely: boolean;
}

class ProxyDetector {
  async getTLSFingerprint(domain: string): Promise<string> {
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
      
      socket.on('error', (err: Error) => {
        reject(err);
      });
      
      socket.setTimeout(5000, () => {
        socket.destroy();
        reject(new Error('TLS handshake timeout'));
      });
    });
  }

  async measureHandshakeTime(domain: string): Promise<number> {
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

  async makeHTTPSRequest(domain: string): Promise<{ headers: http.IncomingHttpHeaders; body: string; latency: number }> {
    return new Promise((resolve, reject) => {
      const startTime = process.hrtime.bigint();
      
      const req = https.request({
        hostname: domain,
        port: 443,
        path: '/',
        method: 'GET',
        headers: { 'User-Agent': 'Mozilla/5.0' }
      }, (res: http.IncomingMessage) => {
        let body = '';
        res.on('data', (chunk: Buffer) => {
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
      
      req.on('error', (err: Error) => reject);
      req.setTimeout(10000, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
      
      req.end();
    });
  }

  async checkBareMux(domain: string): Promise<boolean> {
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
    } catch (error) {
      return false;
    }
  }

  async checkWispServers(domain: string): Promise<boolean> {
    try {
      const response = await this.makeHTTPSRequest(domain);
      const body = response.body.toLowerCase();
      
      const wispIndicators = [
        'websocket tunnel',
        'multiplexed connection',
        'proxy tunnel',
        'socket proxy',
        'tunnel server'
      ];
      
      return wispIndicators.some(indicator => body.includes(indicator));
    } catch (error) {
      return false;
    }
  }

  calculateHeaderEntropy(headers: http.IncomingHttpHeaders): number {
    const headerValues = Object.values(headers).filter(val => val !== undefined);
    const headerString = headerValues.join('');
    const frequency: { [key: string]: number } = {};
    
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

  calculateVariance(values: number[]): number {
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const squaredDiffs = values.map(val => Math.pow(val - mean, 2));
    return squaredDiffs.reduce((sum, val) => sum + val, 0) / values.length;
  }

  async testWebSocketUpgrade(domain: string): Promise<boolean> {
    return new Promise((resolve) => {
      const wsUrl = `wss://${domain}`;
      const ws = new WebSocket(wsUrl, {
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

  async analyzeDomain(domain: string): Promise<ProxyDetectionResult> {
    const numRequests = 5;
    const tlsFingerprints: string[] = [];
    const handshakeTimes: number[] = [];
    const latencies: number[] = [];
    const responseHashes: string[] = [];
    const headerEntropies: number[] = [];
    
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
      } catch (error) {
        continue;
      }
    }
    
    const uniqueFingerprints = new Set(tlsFingerprints).size;
    const uniqueResponseHashes = new Set(responseHashes).size;
    const avgHeaderEntropy = headerEntropies.reduce((sum, val) => sum + val, 0) / headerEntropies.length || 0;
    
    const latencyStats: LatencyStats = {
      min: Math.min(...latencies),
      max: Math.max(...latencies),
      avg: latencies.reduce((sum, val) => sum + val, 0) / latencies.length || 0,
      variance: this.calculateVariance(latencies)
    };
    
    const handshakeVariance = this.calculateVariance(handshakeTimes);
    const websocketUpgrade = await this.testWebSocketUpgrade(domain);
    const isBareMux = await this.checkBareMux(domain);
    const isWispServer = await this.checkWispServers(domain);
    
    let anomalyScore = 0;
    
    if (uniqueFingerprints > 1) {
      anomalyScore += uniqueFingerprints * 0.4;
    }
    
    if (handshakeVariance > 100) {
      anomalyScore += Math.min(handshakeVariance / 100, 1) * 0.4;
    }
    
    if (latencyStats.variance > 800) {
      anomalyScore += Math.min(latencyStats.variance / 800, 1) * 0.3;
    }
    
    if (uniqueResponseHashes > 2) {
      anomalyScore += (uniqueResponseHashes - 2) * 0.2;
    }
    
    if (!websocketUpgrade) {
      anomalyScore += 0.2;
    }
    
    if (isBareMux) {
      anomalyScore += 0.6;
    }
    
    if (isWispServer) {
      anomalyScore += 0.8;
    }
    
    const proxyLikely = anomalyScore > 0.5;
    
    return {
      domain,
      tlsFingerprints,
      handshakeTimes,
      latencyStats,
      headerEntropy: avgHeaderEntropy,
      responseHashConsistency: uniqueResponseHashes === 1,
      websocketUpgrade,
      anomalyScore,
      proxyLikely
    };
  }
}

const app = express();
const detector = new ProxyDetector();
const PORT = process.env.PORT || 3000;

app.get('/v1/dusk/check/url=:domain', async (req: Request, res: Response) => {
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
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;

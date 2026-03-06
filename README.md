# Dusk Proxy Detection API

A Node.js API using TypeScript and Express that analyzes whether a requested domain is being accessed through an interception proxy or MITM proxy.

## Installation

```bash
npm install
```

## Building

```bash
npm run build
```

## Running

```bash
npm start
```

The server will start on port 3000 by default.

## API Endpoint

### GET /v1/dusk/check/url="<domain>"

Analyzes a domain for proxy interception using behavioral and statistical analysis.

#### Example Request
```
GET /v1/dusk/check/url="example.com"
```

#### Response Format
```json
{
  "domain": "example.com",
  "tlsFingerprints": ["sha256:fingerprint1", "sha256:fingerprint2"],
  "handshakeTimes": [45.2, 47.1, 44.8],
  "latencyStats": {
    "min": 120.5,
    "max": 156.3,
    "avg": 135.7,
    "variance": 245.2
  },
  "headerEntropy": 3.14,
  "responseHashConsistency": true,
  "websocketUpgrade": true,
  "anomalyScore": 0.15,
  "proxyLikely": false
}
```

## Detection Methodology

The API uses behavioral analysis rather than hardcoded rules:

1. **TLS Certificate Analysis**: Computes SHA-256 fingerprints across multiple connections
2. **Timing Analysis**: Measures handshake times and request latency variance
3. **Header Entropy**: Calculates statistical entropy of response headers
4. **Response Consistency**: Compares response body hashes across requests
5. **WebSocket Testing**: Attempts WebSocket upgrades to detect interception
6. **Anomaly Scoring**: Dynamically computes scores based on behavioral patterns

The system avoids false positives from legitimate services by focusing on statistical anomalies rather than fixed patterns.

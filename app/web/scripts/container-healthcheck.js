'use strict';

const http = require('node:http');
const https = require('node:https');
const nodeTls = require('node:tls');

const cert = (process.env.FORTIFLOW_TLS_CERT || '').trim();
const key = (process.env.FORTIFLOW_TLS_KEY || '').trim();
const hostname = (process.env.FORTIFLOW_TLS_HOSTNAME || '').trim();
const configured = [cert, key, hostname];

if (configured.some(Boolean) && !configured.every(Boolean)) {
  console.error('Configuration TLS FortiFlow incomplète.');
  process.exit(1);
}

const tls = configured.every(Boolean);
const client = tls ? https : http;
const port = process.env.PORT || '3737';
const request = client.get({
  hostname: '127.0.0.1',
  port,
  path: '/',
  servername: tls ? hostname : undefined,
  headers: tls ? { Host: hostname } : undefined,
  // La chaîne peut venir d'une CA interne absente de l'image ; le SAN est
  // néanmoins contrôlé explicitement ci-dessous.
  rejectUnauthorized: false,
  timeout: 5000,
}, response => {
  if (tls) {
    const hostnameError = nodeTls.checkServerIdentity(
      hostname,
      response.socket.getPeerCertificate(),
    );
    if (hostnameError) {
      response.resume();
      console.error(hostnameError.message);
      process.exit(1);
    }
  }
  response.resume();
  process.exit(response.statusCode === 200 ? 0 : 1);
});
request.on('timeout', () => request.destroy(new Error('healthcheck timeout')));
request.on('error', error => {
  console.error(error.message);
  process.exit(1);
});
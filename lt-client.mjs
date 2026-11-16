// Minimal localtunnel client that works through the egress HTTP proxy.
// Protocol (from the localtunnel lib): allocate a subdomain via
// https://localtunnel.me/<name> (or /?new), then open raw TCP connections to
// localtunnel.me:<port> and proxy them 1:1 to the local HTTP server.
// Direct TCP is blocked on this VM, so the TCP connection is established
// via HTTP CONNECT through the egress proxy (credentials from env only,
// never logged or written to disk).
import net from 'net';
import { execFileSync } from 'child_process';

const LOCAL_PORT = Number(process.argv[2] || 8080);
const SUBDOMAIN = process.argv[3] || '';
const MAX_CONN = 2;

const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy || '';
if (!proxyUrl) { console.error('no proxy in env'); process.exit(1); }
const pu = new URL(proxyUrl);
const proxyHost = pu.hostname;
const proxyPort = Number(pu.port || 3128);
const proxyAuth = pu.username ? `Basic ${Buffer.from(`${decodeURIComponent(pu.username)}:${decodeURIComponent(pu.password)}`).toString('base64')}` : '';

function allocate() {
  const path = SUBDOMAIN ? `/${SUBDOMAIN}` : '/?new';
  const out = execFileSync('curl', ['-s', '-m', '20', `https://localtunnel.me${path}`], { encoding: 'utf8' });
  const info = JSON.parse(out);
  if (!info.url || !info.port) throw new Error('bad allocate response: ' + out);
  return info;
}

function connectViaProxy(host, port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: proxyHost, port: proxyPort });
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('proxy connect timeout')); }, 10000);
    sock.once('error', e => { clearTimeout(timer); reject(e); });
    sock.once('connect', () => {
      const lines = [
        `CONNECT ${host}:${port} HTTP/1.1`,
        `Host: ${host}:${port}`,
      ];
      if (proxyAuth) lines.push(`Proxy-Authorization: ${proxyAuth}`);
      lines.push('', '');
      sock.write(lines.join('\r\n'));
      let buf = Buffer.alloc(0);
      const onData = chunk => {
        buf = Buffer.concat([buf, chunk]);
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        sock.removeListener('data', onData);
        const head = buf.slice(0, idx).toString();
        const rest = buf.slice(idx + 4);
        clearTimeout(timer);
        if (!/^HTTP\/1\.[01] 200/.test(head)) {
          sock.destroy();
          reject(new Error('proxy CONNECT failed: ' + head.split('\r\n')[0]));
          return;
        }
        if (rest.length) sock.unshift(rest);
        resolve(sock);
      };
      sock.on('data', onData);
    });
  });
}

// Probe whether a tunnel port accepts a proxied CONNECT (some localtunnel
// backend servers hang — a dead port must be abandoned, not retried).
async function portWorks(port) {
  try {
    const s = await connectViaProxy('localtunnel.me', port);
    s.destroy();
    return true;
  } catch { return false; }
}

async function allocateWorking() {
  for (let i = 1; i <= 8; i++) {
    const info = allocate();
    console.log(`allocate #${i}: ${info.url} port ${info.port}`);
    if (await portWorks(info.port)) {
      console.log('port works:', info.port);
      return info;
    }
    console.log('port dead, reallocating...');
  }
  throw new Error('no working tunnel port after 8 allocations');
}

let consecutiveFailures = 0;

function openCluster(info) {
  connectViaProxy('localtunnel.me', info.port).then(remote => {
    consecutiveFailures = 0;
    console.log('tunnel connected:', info.url);
    remote.setKeepAlive(true);
    const local = net.connect({ host: '127.0.0.1', port: LOCAL_PORT });
    local.once('error', err => { console.log('local error:', err.message); remote.end(); setTimeout(() => openCluster(info), 1000); });
    remote.once('error', err => { console.log('remote error:', err.message); local.end(); setTimeout(() => openCluster(info), 1000); });
    remote.once('close', () => { local.end(); setTimeout(() => openCluster(info), 1000); });
    local.once('connect', () => {
      remote.pipe(local).pipe(remote);
    });
  }).catch(err => {
    consecutiveFailures++;
    console.log('tunnel connect failed:', err.message, '- retry in 5s (failures:', consecutiveFailures + ')');
    // A dead backend port never recovers — exit so the supervisor restarts
    // us with a fresh allocation (new port).
    if (consecutiveFailures >= 3) { console.log('too many failures — exiting for fresh allocation'); process.exit(1); }
    setTimeout(() => openCluster(info), 5000);
  });
}

const info = await allocateWorking();
console.log('PUBLIC_URL=' + info.url);
for (let i = 0; i < (info.max_conn_count || MAX_CONN); i++) openCluster(info);

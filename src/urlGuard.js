import dns from 'node:dns';
import net from 'node:net';
import ipaddr from 'ipaddr.js';
import { LRUCache } from 'lru-cache';

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

// Ports that are never legitimate image hosts: services browsers refuse to speak HTTP to
// (Fetch "bad ports") plus common databases/admin services. Normal and custom web ports stay allowed.
const BLOCKED_PORTS = new Set(
  [
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95,
    101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161,
    179, 389, 427, 445, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556,
    563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 2375, 2376, 3306,
    3389, 3659, 4045, 4190, 5060, 5061, 5432, 5900, 6000, 6379, 6566, 6665, 6666, 6667,
    6668, 6669, 6679, 6697, 9200, 10080, 11211, 27017
  ].map(String)
);

const BLOCKED_HOSTS = new Set([
  'localhost',
  '0.0.0.0',
  '::1',
  '::'
]);

const BLOCKED_SUFFIXES = [
  '.local',
  '.localhost',
  '.internal',
  '.invalid',
  '.home.arpa',
  '.arpa',
  '.onion',
  '.i2p',
  '.exit',
  '.corp',
  '.lan',
  '.home',
  '.intra',
  '.intranet',
  '.private'
];

const BLOCKED_IPV4_RANGES = new Set([
  'unspecified',
  'private',
  'loopback',
  'linkLocal',
  'broadcast',
  'multicast',
  'reserved',
  'carrierGradeNat'
]);

const DNS_CACHE = new LRUCache({
  max: 1000,
  ttl: 60000
});

function getCachedDns(hostname) {
  return DNS_CACHE.get(hostname) ?? null;
}

function setCachedDns(hostname, data) {
  DNS_CACHE.set(hostname, data);
}

function ssrfError() {
  const error = new Error('SSRF_BLOCKED_DNS');
  error.code = 'SSRF_BLOCKED_DNS';
  return error;
}

function normalizeHost(hostname) {
  let host = String(hostname || '').toLowerCase().trim();

  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }

  if (host.endsWith('.')) {
    host = host.slice(0, -1);
  }

  return host;
}

function isPublicIPv4Compat(ipv4String) {
  // Reuse the same logic as the main IPv4 check.
  // If the embedded IPv4 is private, return false (block it).
  try {
    const addr = ipaddr.parse(ipv4String);
    const range = addr.range();
    if (!range) return false;
    return !BLOCKED_IPV4_RANGES.has(range);
  } catch {
    return false;
  }
}

export function isPublicIP(ip) {
  try {
    // Block IPv4-compatible IPv6 forms like ::192.168.1.1
    // These are deprecated but could be used to bypass SSRF filters.
    const lower = String(ip).toLowerCase();
    const compatMatch = lower.match(/^::(\d+\.\d+\.\d+\.\d+)$/);
    if (compatMatch && !isPublicIPv4Compat(compatMatch[1])) {
      return false;
    }

    let addr = ipaddr.parse(ip);

    if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) {
      addr = addr.toIPv4Address();
    }

        if (addr.kind() === 'ipv6') {
      const lower = addr.toString().toLowerCase();

      // IPv4-compatible ::/96 (deprecated; e.g. ::7f00:1, ::a00:1)
      if (addr.match(ipaddr.parse('::'), 96)) return false;

      // Teredo 2001::/32
      const teredoNetwork = ipaddr.parse('2001:0000::');
      if (addr.match(teredoNetwork, 32)) return false;

      // 6to4 2002::/16
      const sixToFour = ipaddr.parse('2002::');
      if (addr.match(sixToFour, 16)) return false;

      // NAT64 64:ff9b::/48
      const nat64 = ipaddr.parse('64:ff9b::');
      if (addr.match(nat64, 48)) return false;

      // Multicast ff00::/8
      const multicast = ipaddr.parse('ff00::');
      if (addr.match(multicast, 8)) return false;

      // Unique local fc00::/7
      const ula = ipaddr.parse('fc00::');
      if (addr.match(ula, 7)) return false;

      // Link-local fe80::/10
      const linkLocal = ipaddr.parse('fe80::');
      if (addr.match(linkLocal, 10)) return false;

      // Loopback
      if (lower === '::1') return false;

      // Unspecified
      if (lower === '::') return false;
    }

    if (addr.kind() === 'ipv4') {
      const range = addr.range();

      if (!range) return false;

      return !BLOCKED_IPV4_RANGES.has(range);
    }

    const range = addr.range();

    return range === 'unicast';
  } catch {
    return false;
  }
}

export function parseSafeUrl(input) {
  let raw = String(input || '').trim();

  if (!raw) return null;

  if (/^https?%3A/i.test(raw)) {
    try {
      raw = decodeURIComponent(raw);
    } catch {
      return null;
    }
  }

  let url;

  try {
    url = new URL(raw);
  } catch {
    return null;
  }

  if (!ALLOWED_PROTOCOLS.has(url.protocol)) return null;
  if (url.username || url.password) return null;
  if (url.port && BLOCKED_PORTS.has(url.port)) return null;

  const host = normalizeHost(url.hostname);

  if (!host) return null;
  if (BLOCKED_HOSTS.has(host)) return null;

  if (BLOCKED_SUFFIXES.some(suffix => host.endsWith(suffix))) {
    return null;
  }

  if (net.isIP(host) && !isPublicIP(host)) {
    return null;
  }

  return url;
}

export function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  const wantsAll = Boolean(options?.all);
  const family = Number(options?.family) || 0;

  const host = normalizeHost(hostname);

  if (!host) {
    return callback(ssrfError());
  }

  if (BLOCKED_HOSTS.has(host)) {
    return callback(ssrfError());
  }

  if (BLOCKED_SUFFIXES.some(suffix => host.endsWith(suffix))) {
    return callback(ssrfError());
  }

  if (net.isIP(host)) {
    if (!isPublicIP(host)) {
      return callback(ssrfError());
    }

    const ipFamily = net.isIPv6(host) ? 6 : 4;

    if (family && family !== 0 && family !== ipFamily) {
      return callback(ssrfError());
    }

    if (wantsAll) {
      return callback(null, [{ address: host, family: ipFamily }]);
    }

    return callback(null, host, ipFamily);
  }

  const cached = getCachedDns(host);
  if (cached) {
    let addresses = cached.slice();

    if (family === 4) addresses = addresses.filter(a => a.family === 4);
    if (family === 6) addresses = addresses.filter(a => a.family === 6);

    if (!addresses.length) return callback(ssrfError());

    addresses.sort((a, b) => {
      if (a.family === b.family) return 0;
      return a.family === 4 ? -1 : 1;
    });

    if (wantsAll) return callback(null, addresses);
    const chosen = addresses[0];
    return callback(null, chosen.address, chosen.family);
  }

  const tasks = [];

  if (!family || family === 0 || family === 4) {
    tasks.push(dns.promises.resolve4(host).catch(() => []));
  }

  if (!family || family === 0 || family === 6) {
    tasks.push(dns.promises.resolve6(host).catch(() => []));
  }

  Promise.all(tasks)
    .then(([v4 = [], v6 = []]) => {
      const addresses = [];

      for (const address of v4) {
        if (isPublicIP(address)) {
          addresses.push({ address, family: 4 });
        }
      }

      for (const address of v6) {
        if (isPublicIP(address)) {
          addresses.push({ address, family: 6 });
        }
      }

      if (!addresses.length) {
        return callback(ssrfError());
      }

      setCachedDns(host, addresses);

      addresses.sort((a, b) => {
        if (a.family === b.family) return 0;
        return a.family === 4 ? -1 : 1;
      });

      if (wantsAll) {
        return callback(null, addresses);
      }

      const chosen = addresses[0];
      return callback(null, chosen.address, chosen.family);
    })
    .catch(err => {
      callback(err);
    });
          }

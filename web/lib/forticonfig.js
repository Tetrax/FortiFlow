'use strict';

// ─── FortiGate config section parser ─────────────────────────────────────────
// Extrait les blocs : config X / edit "name" / set key val / next / end
// Gère la profondeur pour ignorer les sections imbriquées sans les parser.

function extractSection(lines, sectionName) {
  return extractSections(lines, [sectionName])[sectionName];
}

// Multi-section single-pass scanner.
// Accepts an array of section names, returns { [sectionName]: { [editName]: props } }
function extractSections(lines, sectionNames) {
  // Build a Set for O(1) lookup
  const wanted   = new Set(sectionNames);
  // Results map: sectionName → {}
  const results  = {};
  for (const name of sectionNames) results[name] = {};

  let depth      = 0;
  let inTarget   = null;  // current section name being parsed, or null
  let editName   = null;
  let editProps  = {};

  for (const rawLine of lines) {
    const t = rawLine.trim();
    if (!t || t.startsWith('#')) continue;

    if (inTarget === null) {
      // Not inside any target section — check for a new target header
      if (t.startsWith('config ')) {
        const candidate = t.slice(7).trim();
        if (wanted.has(candidate)) {
          inTarget  = candidate;
          depth     = 1;
          editName  = null;
          editProps = {};
        }
      }
      continue;
    }

    // Inside a target section
    if (t.startsWith('config ')) { depth++; continue; }
    if (t === 'end') {
      if (--depth === 0) {
        // Flush last pending edit (some sections have no 'next' before 'end')
        if (editName !== null) results[inTarget][editName] = editProps;
        inTarget  = null;
        editName  = null;
        editProps = {};
      }
      continue;
    }

    if (depth !== 1) continue; // ignore nested section content

    if (t.startsWith('edit ')) {
      if (editName !== null) results[inTarget][editName] = editProps;
      editName  = t.slice(5).trim().replace(/^"|"$/g, '');
      editProps = {};
    } else if (t === 'next') {
      if (editName !== null) results[inTarget][editName] = editProps;
      editName  = null;
      editProps = {};
    } else if (t.startsWith('set ')) {
      const rest = t.slice(4).trim();
      const idx  = rest.indexOf(' ');
      if (idx > 0) {
        editProps[rest.slice(0, idx)] = rest.slice(idx + 1).trim().replace(/^"|"$/g, '');
      } else {
        editProps[rest] = '';
      }
    }
  }

  return results;
}

// ─── Subnet helpers ───────────────────────────────────────────────────────────

function maskBits(mask) {
  return mask.split('.').reduce((acc, o) => {
    let n = parseInt(o, 10), b = 0;
    while (n) { b += n & 1; n >>>= 1; }
    return acc + b;
  }, 0);
}

function maskToPrefix(mask) {
  return mask.includes('.') ? maskBits(mask) : parseInt(mask, 10);
}

function ip2int(ip) {
  return ip.split('.').reduce((a, o) => (a * 256) + parseInt(o, 10), 0) >>> 0;
}

function int2ip(n) {
  return [(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF].join('.');
}

function cidrToMask(prefix) {
  const bits = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return int2ip(bits);
}

function networkAddress(ip, prefix) {
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return int2ip(ip2int(ip) & mask);
}

// "192.168.1.0 255.255.255.0" → "192.168.1.0/24"
function fortiSubnetToCIDR(subnet) {
  if (!subnet) return null;
  const parts = subnet.trim().split(/\s+/);
  if (parts.length === 2) return `${parts[0]}/${maskBits(parts[1])}`;
  if (parts.length === 1 && parts[0].includes('/')) return parts[0];
  return null;
}

function parsePorts(portrange) {
  if (!portrange) return [];
  const ports = [];
  for (const part of portrange.trim().split(/\s+/)) {
    const [a, b] = part.split('-').map(Number);
    if (b && !isNaN(b)) { for (let i = a; i <= Math.min(b, a + 100); i++) ports.push(i); }
    else if (a && !isNaN(a)) ports.push(a);
  }
  return ports;
}

// ─── FortiGate predefined services ───────────────────────────────────────────
// Mapping port+proto → nom de service prédéfini FortiGate

const PREDEFINED = {
  // TCP
  20: { proto: 'tcp', name: 'FTP'          },
  21: { proto: 'tcp', name: 'FTP'          },
  22: { proto: 'tcp', name: 'SSH'          },
  23: { proto: 'tcp', name: 'TELNET'       },
  25: { proto: 'tcp', name: 'SMTP'         },
  53: { proto: 'both', name: 'DNS'         },
  80: { proto: 'tcp', name: 'HTTP'         },
  88: { proto: 'both', name: 'KERBEROS'    },
 110: { proto: 'tcp', name: 'POP3'         },
 119: { proto: 'tcp', name: 'NNTP'         },
 135: { proto: 'tcp', name: 'DCE-RPC'      },
 139: { proto: 'tcp', name: 'SAMBA'        },
 143: { proto: 'tcp', name: 'IMAP'         },
 179: { proto: 'tcp', name: 'BGP'          },
 389: { proto: 'tcp', name: 'LDAP'         },
 443: { proto: 'tcp', name: 'HTTPS'        },
 445: { proto: 'tcp', name: 'SMB'          },
 465: { proto: 'tcp', name: 'SMTP'         },
 587: { proto: 'tcp', name: 'SMTP'         },
 636: { proto: 'tcp', name: 'LDAPS'        },
 993: { proto: 'tcp', name: 'IMAPS'        },
 995: { proto: 'tcp', name: 'POP3S'        },
1433: { proto: 'tcp', name: 'MS-SQL-S'     },
1434: { proto: 'udp', name: 'MS-SQL-M'     },
1521: { proto: 'tcp', name: 'ORACLE'       },
1723: { proto: 'tcp', name: 'PPTP'         },
2049: { proto: 'both', name: 'NFS'         },
3268: { proto: 'tcp', name: 'LDAP'         },
3306: { proto: 'tcp', name: 'MySQL'        },
3389: { proto: 'tcp', name: 'RDP'          },
3690: { proto: 'tcp', name: 'SVN'          },
5432: { proto: 'tcp', name: 'PostgreSQL'   },
5900: { proto: 'tcp', name: 'VNC'          },
5985: { proto: 'tcp', name: 'WinRM-HTTP'   },
5986: { proto: 'tcp', name: 'WinRM-HTTPS'  },
8080: { proto: 'tcp', name: 'HTTP'         },
8443: { proto: 'tcp', name: 'HTTPS'        },
 // UDP
  67: { proto: 'udp', name: 'DHCP'         },
  68: { proto: 'udp', name: 'DHCP'         },
  69: { proto: 'udp', name: 'TFTP'         },
 123: { proto: 'udp', name: 'NTP'          },
 137: { proto: 'udp', name: 'NetBIOS_NS'   },
 138: { proto: 'udp', name: 'NetBIOS_DS'   },
 161: { proto: 'udp', name: 'SNMP'         },
 162: { proto: 'udp', name: 'SNMP_TRAP'    },
 500: { proto: 'udp', name: 'IKE'          },
 514: { proto: 'udp', name: 'SYSLOG'       },
1194: { proto: 'udp', name: 'OPENVPN'      },
1812: { proto: 'udp', name: 'RADIUS'       },
4500: { proto: 'udp', name: 'IKE'          },
};

function findPredefinedService(port, proto) {
  const p = parseInt(port, 10);
  if (!p) return null;
  const isUdp = /^(udp|17)$/i.test(String(proto));
  const entry = PREDEFINED[p];
  if (!entry) return null;
  if (entry.proto === 'both') return entry.name;
  if (isUdp && entry.proto === 'udp')   return entry.name;
  if (!isUdp && entry.proto === 'tcp')  return entry.name;
  return null;
}

// ─── RFC1918 helper ───────────────────────────────────────────────────────────

const RFC1918 = [
  { start: ip2int('10.0.0.0'),    end: ip2int('10.255.255.255')  },
  { start: ip2int('172.16.0.0'),  end: ip2int('172.31.255.255')  },
  { start: ip2int('192.168.0.0'), end: ip2int('192.168.255.255') },
];
function isPrivateIP(ip) {
  try { const n = ip2int(ip); return RFC1918.some(r => n >= r.start && n <= r.end); }
  catch { return false; }
}

// ─── Main config parser ───────────────────────────────────────────────────────

function parseFortiConfig(text) {
  const lines = text.split(/\r?\n/);

  // ── Raw section extraction — single pass for all sections ──
  const _sections     = extractSections(lines, [
    'firewall address',
    'firewall service custom',
    'firewall addrgrp',
    'firewall service group',
    'firewall policy',
    'system interface',
    'system zone',
    'router static',
  ]);
  const rawAddresses  = _sections['firewall address'];
  const rawCustomSvcs = _sections['firewall service custom'];
  const rawInterfaces = _sections['system interface'];
  const rawZones      = _sections['system zone'];

  // SDWAN : FortiOS 7.x uses "system sdwan", 6.x uses "system virtual-wan-link"
  const sdwanMembers  = parseSdwanMembers(text);
  const sdwanEnabled  = sdwanMembers.length > 0;
  // Virtual interface/zone name used in policies for SD-WAN traffic
  // FortiOS 6.x: "virtual-wan-link", FortiOS 7.x: zone name (often "virtual-wan-link" or custom)
  // Parse ALL SDWAN zone names from config system sdwan > config zone
  const sdwanZoneNames = (() => {
    if (!sdwanEnabled) return [];
    const zonesBlock = text.match(/config system sdwan[\s\S]*?config zone([\s\S]*?)^\s*end/m);
    if (!zonesBlock) return [];
    const names = [];
    for (const m of zonesBlock[1].matchAll(/edit\s+"?([^\s"]+)"?/g)) names.push(m[1]);
    return names;
  })();
  // Default SDWAN zone: prefer zone that has members assigned (set zone "X" in members)
  const sdwanZoneName = (() => {
    if (!sdwanEnabled) return null;
    const membersBlock = text.match(/config system sdwan[\s\S]*?config members([\s\S]*?)^\s*end/m);
    if (membersBlock) {
      const zm = membersBlock[1].match(/set zone\s+"?([^\s"]+)"?/);
      if (zm) return zm[1];
    }
    return sdwanZoneNames[0] || 'virtual-wan-link';
  })();

  // ── Addresses ──
  const addresses = {};
  for (const [name, props] of Object.entries(rawAddresses)) {
    let cidr = null;
    if (props.subnet)   cidr = fortiSubnetToCIDR(props.subnet);
    else if (props.fqdn) cidr = props.fqdn;
    else if (props['start-ip']) cidr = props['start-ip']; // IP range — use start
    addresses[name] = { name, type: props.type || 'ipmask', cidr, fqdn: props.fqdn || '' };
  }

  // ── Address groups ──
  const rawAddrGroups = _sections['firewall addrgrp'];
  const addressGroups = {};
  for (const [name, props] of Object.entries(rawAddrGroups)) {
    const members = (props.member || '').split(/\s+/)
      .map(m => m.replace(/^"|"$/g, '')).filter(Boolean);
    // Resolve member CIDRs from addresses
    const memberCidrs = members.map(m => addresses[m]?.cidr).filter(Boolean);
    addressGroups[name] = { name, members, memberCidrs };
  }

  // ── Custom services ──
  const customServices = {};
  for (const [name, props] of Object.entries(rawCustomSvcs)) {
    customServices[name] = {
      name,
      proto:    (props.protocol || 'TCP/UDP/SCTP').toUpperCase(),
      tcpPorts: parsePorts(props['tcp-portrange'] || ''),
      udpPorts: parsePorts(props['udp-portrange'] || ''),
    };
  }

  // ── Service groups ──
  const rawSvcGroups = _sections['firewall service group'];
  const serviceGroups = {};
  for (const [name, props] of Object.entries(rawSvcGroups)) {
    const members = (props.member || '').match(/"([^"]+)"/g)?.map(m => m.replace(/"/g, ''))
                    || (props.member || '').split(/\s+/).filter(Boolean).map(m => m.replace(/^"|"$/g, ''));
    serviceGroups[name] = { name, members };
  }

  // ── Existing firewall policies ──
  const rawPolicies = _sections['firewall policy'];
  const existingPolicies = [];
  const parseMultiVal = (val) => (val || '').match(/"([^"]+)"/g)?.map(m => m.replace(/"/g, ''))
                                 || (val || '').split(/\s+/).filter(Boolean).map(v => v.replace(/^"|"$/g, ''));
  for (const [editId, props] of Object.entries(rawPolicies)) {
    existingPolicies.push({
      policyid:  parseInt(editId, 10) || editId,
      name:      (props.name || '').replace(/^"|"$/g, ''),
      srcintf:   parseMultiVal(props.srcintf),
      dstintf:   parseMultiVal(props.dstintf),
      srcaddr:   parseMultiVal(props.srcaddr),
      dstaddr:   parseMultiVal(props.dstaddr),
      service:   parseMultiVal(props.service),
      action:    (props.action || 'deny').replace(/^"|"$/g, ''),
      nat:       props.nat === 'enable',
      status:    (props.status || 'enable').replace(/^"|"$/g, ''),
      comments:  (props.comments || '').replace(/^"|"$/g, ''),
    });
  }

  // ── Interfaces ──
  const interfaces = {};
  for (const [name, props] of Object.entries(rawInterfaces)) {
    if (props.type === 'loopback' || props.status === 'down') continue;

    let cidr = null, prefix = null;
    if (props.ip) {
      const parts = props.ip.trim().split(/\s+/);
      if (parts.length === 2) {
        prefix = maskBits(parts[1]);
        const network = networkAddress(parts[0], prefix);
        cidr = `${network}/${prefix}`;
      }
    }
    // Tunnel = explicitement type tunnel ET sans vlanid (les sous-interfaces VLAN ne sont jamais des tunnels)
    const isTunnel = props.type === 'tunnel' && !props.vlanid;
    // WAN : priorité au set role (lan/dmz/undefined = LAN, wan = WAN), sinon détection par IP
    const roleLan = props.role === 'lan' || props.role === 'dmz';
    const roleWan = props.role === 'wan';
    const isWan = !isTunnel && (roleWan || (!roleLan && !isPrivateIP(props.ip?.split(' ')[0] || '') && !!props.ip));
    interfaces[name] = {
      name,
      rawIp:  props.ip || '',
      cidr,
      prefix,
      alias:  props.alias || name,
      type:   props.type  || 'physical',
      isWan,
      isTunnel,
      isSdwan: sdwanMembers.includes(name),
    };
  }

  // ── Zones ──
  const zones = {};
  for (const [name, props] of Object.entries(rawZones)) {
    const members = (props.interface || '').split(/\s+/)
      .filter(Boolean).map(m => m.replace(/^"|"$/g, ''));
    const allWan = members.length > 0 && members.every(m => interfaces[m]?.isWan);
    zones[name] = { name, members, isWan: allWan };
  }

  // ── SDWAN zones (config system sdwan > config members: set interface / set zone) ──
  // These are NOT in config system zone, so we parse them separately
  const sdwanMembersBlock = text.match(/config system sdwan[\s\S]*?config members([\s\S]*?)^\s*end/m);
  if (sdwanMembersBlock) {
    // Split by "edit N" to get individual member entries
    const entries = sdwanMembersBlock[1].split(/^\s*edit\s+\d+/m).filter(Boolean);
    for (const entry of entries) {
      const ifaceM = entry.match(/set interface\s+"?([^\s"]+)"?/);
      const zoneM  = entry.match(/set zone\s+"?([^\s"]+)"?/);
      if (ifaceM && zoneM) {
        const ifaceName = ifaceM[1];
        const zoneName  = zoneM[1];
        if (!zones[zoneName]) {
          zones[zoneName] = { name: zoneName, members: [], isWan: true };
        }
        if (!zones[zoneName].members.includes(ifaceName)) {
          zones[zoneName].members.push(ifaceName);
        }
      }
    }
  }

  // ── Routes statiques ──
  const staticRoutes = parseStaticRoutes(_sections['router static']);

  // ── BGP ──
  const bgpNeighborIntfs = parseBgpNeighborIntfs(text);
  // BGP actif seulement si des voisins avec remote-as sont configurés
  const hasBgp = bgpNeighborIntfs.size > 0 || hasBgpNeighbors(text);

  // Ajouter les voisins BGP comme pseudo-routes /32 (host routes)
  for (const [ip, intf] of bgpNeighborIntfs) {
    staticRoutes.push({ dst: `${ip}/32`, gateway: ip, device: intf, distance: 0, priority: 0 });
  }
  sortRoutes(staticRoutes);

  // Table de routes unifiée : statiques + connected (depuis les interfaces)
  const fullRoutes = buildFullRouteTable(staticRoutes, interfaces);

  // Effective SD-WAN interface name to use in policies
  const sdwanIntfName = sdwanEnabled ? (sdwanZoneName || 'virtual-wan-link') : null;

  // VDOM detection (multi-VDOM FortiGate) — parseur partiel, warning UI seulement
  const hasVdom = /^config vdom\s*$/m.test(text);

  // OSPF detection — vérifie la présence de networks configurés
  const hasOspf = /config router ospf[\s\S]*?set router-id\s+\d/m.test(text);

  return { addresses, addressGroups, customServices, serviceGroups, interfaces, zones, sdwanMembers, sdwanZoneNames, sdwanEnabled, sdwanIntfName, hasVdom, staticRoutes, fullRoutes, hasBgp, hasOspf, existingPolicies };
}

// ─── Static routes + BGP parser ──────────────────────────────────────────────

// Extrait config router static → [{dst, device, gateway, distance, priority}]
// Trié par préfixe le plus long d'abord, puis distance croissante
// rawRoutes peut être un objet pré-extrait (depuis extractSections) ou un tableau de lignes (compat)
function parseStaticRoutes(rawRoutesOrLines) {
  const rawRoutes = Array.isArray(rawRoutesOrLines)
    ? extractSection(rawRoutesOrLines, 'router static')
    : (rawRoutesOrLines || {});
  const routes = [];

  for (const [, props] of Object.entries(rawRoutes)) {
    const dst    = (props.dst      || '').trim();
    const device = (props.device   || props.interface || '').trim().replace(/^"|"$/g, '');
    if (!device || !dst) continue;

    // FortiGate "set dst X.X.X.X M.M.M.M" → CIDR
    const parts = dst.split(/\s+/);
    let cidr;
    if (parts.length === 2) {
      const bits = maskBits(parts[1]);
      if (bits === null) continue;
      cidr = `${parts[0]}/${bits}`;
    } else {
      cidr = parts[0].includes('/') ? parts[0] : `${parts[0]}/32`;
    }

    routes.push({
      dst:      cidr,
      gateway:  (props.gateway || '').trim(),
      device,
      distance: parseInt(props.distance || '10', 10),
      priority: parseInt(props.priority || '0',  10),
    });
  }

  sortRoutes(routes);
  return routes;
}

function sortRoutes(routes) {
  routes.sort((a, b) => {
    const aLen = parseInt(a.dst.split('/')[1] || '0', 10);
    const bLen = parseInt(b.dst.split('/')[1] || '0', 10);
    return bLen !== aLen ? bLen - aLen : a.distance - b.distance;
  });
}

// Vérifie si des voisins BGP avec remote-as sont réellement configurés
function hasBgpNeighbors(text) {
  const bgpSection = text.match(/config router bgp([\s\S]*?)^end\b/m);
  if (!bgpSection) return false;
  // Cherche un bloc neighbor avec un set remote-as (preuve d'un voisin réel)
  return /edit\s+"?\d+\.\d+\.\d+\.\d+"?[\s\S]*?set remote-as\s+\d+/m.test(bgpSection[1]);
}

// Extrait les interfaces des voisins BGP → Map<neighborIp, interfaceName>
function parseBgpNeighborIntfs(text) {
  const map = new Map();
  const bgpSection = text.match(/config router bgp([\s\S]*?)^end\b/m);
  if (!bgpSection) return map;
  for (const block of bgpSection[1].matchAll(/edit\s+"?(\d+\.\d+\.\d+\.\d+)"?([\s\S]*?)next/g)) {
    const intfM = block[2].match(/set interface\s+"?([^\s"]+)"?/);
    if (intfM) map.set(block[1], intfM[1]);
  }
  return map;
}

// Génère des pseudo-routes "connected" depuis les interfaces (subnet → interface)
function buildConnectedRoutes(interfaces) {
  const routes = [];
  for (const [name, iface] of Object.entries(interfaces)) {
    if (!iface.cidr) continue;
    const [ifIp, pfxStr] = iface.cidr.split('/');
    const pfx = parseInt(pfxStr, 10);
    if (pfx <= 0 || pfx > 30) continue; // skip /0, /31, /32
    const net = networkAddress(ifIp, pfx);
    routes.push({ dst: `${net}/${pfx}`, device: name, gateway: '', distance: 0, priority: 0, source: 'connected' });
  }
  return routes;
}

// Construit la table de routes unifiée : statiques + connected (interfaces)
function buildFullRouteTable(staticRoutes, interfaces) {
  const connected = buildConnectedRoutes(interfaces);
  const all = [...staticRoutes, ...connected];
  sortRoutes(all);
  return all;
}

// Longest-prefix match dans la table de routes
// skipDefault=true pour les recherches srcintf (pas de fallback 0.0.0.0/0)
function findInterfaceByRoute(dstCidr, routes, skipDefault) {
  if (!routes || routes.length === 0) return null;
  let targetIp = (dstCidr || '').split('/')[0];
  let targetInt;
  try { targetInt = ip2int(targetIp); } catch { return null; }

  // Passe 1 : routes spécifiques (préfixe > 0)
  for (const route of routes) {
    if (route.dst === '0.0.0.0/0') continue;
    const [routeIp, pfxStr] = route.dst.split('/');
    const pfx  = parseInt(pfxStr, 10);
    const mask = (0xFFFFFFFF << (32 - pfx)) >>> 0;
    try {
      if ((ip2int(routeIp) & mask) === (targetInt & mask)) return route.device;
    } catch { continue; }
  }

  // Passe 2 : route par défaut (sauf pour srcintf)
  if (skipDefault) return null;
  const def = routes.find(r => r.dst === '0.0.0.0/0');
  return def?.device || null;
}

// Parse SDWAN members from raw text (handles nested config)
function parseSdwanMembers(text) {
  const members = [];
  // Try "system sdwan" (FortiOS 7.x)
  let match = text.match(/config system sdwan[\s\S]*?config members([\s\S]*?)^\s*end/m);
  if (!match) {
    // Try "system virtual-wan-link" (FortiOS 6.x)
    match = text.match(/config system virtual-wan-link[\s\S]*?config members([\s\S]*?)^\s*end/m);
  }
  if (match) {
    const section = match[1];
    for (const m of section.matchAll(/set interface\s+"?([^\s"]+)"?/g)) {
      members.push(m[1]);
    }
  }
  return members;
}

// ─── Subnet → Interface matcher ───────────────────────────────────────────────

// Trouve l'interface FortiGate dans laquelle se trouve un sous-réseau donné
function findInterfaceForSubnet(cidr, interfaces) {
  if (!cidr) return null;
  const [subnetIp] = cidr.split('/');
  const targetNet  = ip2int(subnetIp);

  let bestMatch = null, bestPrefix = -1;

  for (const iface of Object.values(interfaces)) {
    if (!iface.cidr) continue;
    const [ifIp, ifPfxStr] = iface.cidr.split('/');
    const ifPfx = parseInt(ifPfxStr, 10);
    const mask = ifPfx === 0 ? 0 : (0xFFFFFFFF << (32 - ifPfx)) >>> 0;
    if ((ip2int(ifIp) & mask) === (targetNet & mask) && ifPfx >= bestPrefix) {
      bestMatch = iface;
      bestPrefix = ifPfx;
    }
  }
  return bestMatch;
}

// Détecte les interfaces candidates pour le WAN (internet)
function detectWanCandidates(interfaces, zones, sdwanMembers) {
  const wanIntfs = Object.values(interfaces).filter(i => i.isWan || i.isSdwan);
  const wanZones = Object.values(zones).filter(z => z.isWan);
  return {
    interfaces: wanIntfs,
    zones:      wanZones,
    sdwan:      sdwanMembers,
  };
}

// ─── Address / Service matching ───────────────────────────────────────────────

function findAddress(cidr, addresses) {
  if (!cidr) return { found: false };
  const matches = [];
  for (const [name, addr] of Object.entries(addresses)) {
    if (addr.cidr === cidr) { matches.push({ name, cidr: addr.cidr }); continue; }
    if (cidr.endsWith('/32')) {
      const ip = cidr.slice(0, -3);
      if (addr.cidr === ip || addr.cidr === `${ip}/32`) matches.push({ name, cidr: addr.cidr });
    }
  }
  if (matches.length === 0) return { found: false };
  return { found: true, name: matches[0].name, allMatches: matches };
}

// Cherche un groupe d'adresses existant contenant exactement les CIDRs donnés
function findAddressGroup(cidrs, addressGroups, addresses) {
  if (!cidrs || cidrs.length < 2 || !addressGroups) return null;
  const sortedCidrs = [...cidrs].sort();
  for (const [name, grp] of Object.entries(addressGroups)) {
    const grpCidrs = grp.members
      .map(m => addresses[m]?.cidr)
      .filter(Boolean)
      .sort();
    if (grpCidrs.length === sortedCidrs.length && grpCidrs.every((c, i) => c === sortedCidrs[i])) {
      return { name, members: grp.members };
    }
  }
  return null;
}

function findServiceGroup(serviceNames, serviceGroups) {
  if (!serviceNames || serviceNames.length < 2 || !serviceGroups) return null;
  const sorted = [...serviceNames].sort();
  for (const [name, grp] of Object.entries(serviceGroups)) {
    const grpSorted = [...grp.members].sort();
    if (grpSorted.length === sorted.length && grpSorted.every((m, i) => m === sorted[i])) {
      return { name, members: grp.members };
    }
  }
  return null;
}

function validateAgainstExisting(generatedPolicies, existingPolicies) {
  if (!existingPolicies || existingPolicies.length === 0) return [];
  const warnings = [];
  for (let gi = 0; gi < generatedPolicies.length; gi++) {
    const gen = generatedPolicies[gi];
    const genSrc = new Set(Array.isArray(gen.srcaddr) ? gen.srcaddr : [gen.srcAddrName].filter(Boolean));
    const genDst = new Set(Array.isArray(gen.dstaddr) ? gen.dstaddr : [gen.dstAddrName].filter(Boolean));
    const genSvc = new Set(gen.serviceNames || []);
    if (genSrc.size === 0 || genDst.size === 0) continue;

    for (const exist of existingPolicies) {
      if (exist.status === 'disable') continue;
      const exSrc = new Set(exist.srcaddr);
      const exDst = new Set(exist.dstaddr);
      const exSvc = new Set(exist.service);

      const srcOverlap = [...genSrc].some(s => exSrc.has(s));
      const dstOverlap = [...genDst].some(d => exDst.has(d));
      if (!srcOverlap || !dstOverlap) continue;

      const svcExact = genSvc.size === exSvc.size && [...genSvc].every(s => exSvc.has(s));
      const svcOverlap = [...genSvc].some(s => exSvc.has(s)) || exSvc.has('ALL') || genSvc.has('ALL');

      if (svcExact) {
        warnings.push({ generatedIdx: gi, type: 'duplicate', existingPolicyId: exist.policyid,
          detail: `Doublon: policy ${exist.policyid} (${exist.srcaddr.join(',')} → ${exist.dstaddr.join(',')}, ${exist.service.join(',')})` });
      } else if (svcOverlap) {
        const common = [...genSvc].filter(s => exSvc.has(s));
        warnings.push({ generatedIdx: gi, type: 'overlap', existingPolicyId: exist.policyid,
          detail: `Chevauchement: policy ${exist.policyid} — services communs: ${common.join(', ') || 'ALL'}` });
      }
    }
  }
  return warnings;
}

function findService(port, protoName, customServices) {
  const p     = parseInt(port, 10);
  const isUdp = /^(udp|17)$/i.test(String(protoName));

  const matches = [];

  // Check predefined
  const predef = findPredefinedService(p, protoName);
  if (predef) matches.push({ name: predef, source: 'predefined' });

  // Check custom services from config (may be multiple)
  for (const [name, svc] of Object.entries(customServices)) {
    const ports = isUdp ? svc.udpPorts : svc.tcpPorts;
    if (ports.includes(p)) matches.push({ name, source: 'custom' });
  }

  if (matches.length === 0) return { found: false };
  return { found: true, name: matches[0].name, source: matches[0].source, allMatches: matches };
}

// ─── Policy analysis ──────────────────────────────────────────────────────────

function suggestAddrName(cidr) {
  return 'FF_' + (cidr || '').replace(/\//g, '_').replace(/\./g, '_');
}

function analyzePolicies(policies, fortiConfig, preferredWanIntf) {
  const { addresses, customServices, interfaces, zones } = fortiConfig;

  return policies.map(p => {
    // Source address
    const srcAddrMatch = findAddress(p.srcSubnet, addresses);
    // Destination address
    let dstAddrMatch;
    if (p.dstType === 'public') {
      dstAddrMatch = { found: true, name: 'all', source: 'builtin' };
    } else {
      dstAddrMatch = findAddress(p.dstTarget, addresses);
    }

    // Services
    const protoLabel = p.protos?.[0] || 'TCP';
    const serviceItems = [];

    if (p.services && p.services.length > 0) {
      for (const svc of p.services) {
        const knownPredef = Object.values(PREDEFINED).some(e => e.name === svc);
        const customMatch = customServices[svc];

        // Build port hint for tooltip
        let portHint = '';
        if (customMatch) {
          const tcp = customMatch.tcpPorts.slice(0, 8).join(', ');
          const udp = customMatch.udpPorts.slice(0, 8).join(', ');
          portHint = [tcp && `TCP: ${tcp}`, udp && `UDP: ${udp}`].filter(Boolean).join(' / ');
        } else if (knownPredef) {
          const entries = Object.entries(PREDEFINED).filter(([, e]) => e.name === svc);
          portHint = entries.map(([port, e]) => `${e.proto.toUpperCase()}: ${port}`).join(', ');
        } else if (p.ports?.length) {
          // Inconnu — montrer les ports observés dans les logs pour ce flux
          const proto = protoLabel;
          portHint = p.ports.slice(0, 8).map(pt => `${proto}: ${pt}`).join(', ') + ' (observé)';
        }

        // Ignorer les services ISDB (ni predefined ni custom) — on ne garde
        // que les vrais services avec port/proto connu
        if (!knownPredef && !customMatch) continue;
        serviceItems.push({
          label: svc,
          found: true,
          name:  svc,
          source: knownPredef ? 'predefined' : 'custom',
          suggestedName: svc,
          isNamed: true,
          portHint,
        });
      }
    }
    // Fallback sur les ports bruts si aucun service nommé reconnu (ou tous ISDB)
    if (serviceItems.length === 0 && p.ports?.length) {
      for (const port of p.ports.slice(0, 10)) {
        const match = findService(port, protoLabel, customServices);
        serviceItems.push({
          label: `${port}/${protoLabel}`,
          port,
          proto: protoLabel,
          portHint: `${protoLabel}: ${port}`,
          found: match.found,
          name:  match.found ? match.name : null,
          source: match.source || null,
          suggestedName: `FF_SVC_${port}_${protoLabel}`,
        });
      }
    }

    // Auto-detect source interface (full route table: static + connected, no default route fallback)
    const routes = fortiConfig.fullRoutes || fortiConfig.staticRoutes || [];
    let srcIfaceName   = null;
    let srcIfaceSource = 'auto'; // 'route' | 'connected' | 'subnet'
    const srcRouteDevice = findInterfaceByRoute(p.srcSubnet, routes, true);
    if (srcRouteDevice) {
      srcIfaceName   = srcRouteDevice;
      srcIfaceSource = 'route';
    }

    // Auto-detect destination interface
    let dstIface = null;
    let dstIfaceName = null;
    let dstIfaceSource = 'auto'; // 'route' | 'sdwan' | 'subnet' | 'wan-candidate'

    if (p.dstType === 'public') {
      // 1. User override (SD-WAN priority selection)
      if (preferredWanIntf) {
        dstIfaceName   = preferredWanIntf;
        dstIfaceSource = 'sdwan';
      } else {
        // 2. Route lookup (default route ou route spécifique)
        const routeDevice = findInterfaceByRoute(p.dstTarget || '0.0.0.0', routes);
        if (routeDevice) {
          // Si SD-WAN actif et que la route pointe vers un membre SD-WAN → utiliser l'interface virtuelle
          if (fortiConfig.sdwanEnabled && fortiConfig.sdwanMembers.includes(routeDevice)) {
            dstIfaceName   = fortiConfig.sdwanIntfName || routeDevice;
            dstIfaceSource = 'sdwan';
          } else {
            dstIfaceName   = routeDevice;
            dstIfaceSource = 'route';
          }
        } else if (fortiConfig.sdwanEnabled && fortiConfig.sdwanIntfName) {
          dstIfaceName   = fortiConfig.sdwanIntfName;
          dstIfaceSource = 'sdwan';
        } else {
          const wanCands = detectWanCandidates(interfaces, zones, fortiConfig.sdwanMembers);
          dstIface       = wanCands.interfaces[0] || null;
          dstIfaceName   = dstIface?.name || null;
          dstIfaceSource = 'wan-candidate';
        }
      }
    } else {
      // 1. Route lookup (plus précis que le matching par subnet)
      const routeDevice = findInterfaceByRoute(p.dstTarget, routes);
      if (routeDevice) {
        dstIfaceName   = routeDevice;
        dstIfaceSource = 'route';
      } else {
        // 2. Fallback : subnet-to-interface matching
        dstIface       = findInterfaceForSubnet(p.dstTarget, interfaces);
        dstIfaceName   = dstIface?.name || null;
        dstIfaceSource = 'subnet';
      }
    }

    // Zone match for src/dst
    const srcZone = Object.values(zones).find(z => z.members.includes(srcIfaceName)) || null;
    const dstZone = Object.values(zones).find(z => z.members.includes(dstIfaceName)) || null;

    const needsWork = !srcAddrMatch.found
      || (!dstAddrMatch.found)
      || serviceItems.some(s => !s.found);

    return {
      ...p,
      analysis: {
        srcAddr:    { ...srcAddrMatch,  cidr: p.srcSubnet, suggestedName: suggestAddrName(p.srcSubnet) },
        dstAddr:    { ...dstAddrMatch,  cidr: p.dstTarget, suggestedName: suggestAddrName(p.dstTarget) },
        services:   serviceItems,
        srcIface:       srcIfaceName   || null,
        srcIfaceSource: srcIfaceSource,
        srcZone:        srcZone?.name  || null,
        dstIface:       dstIfaceName   || null,
        dstIfaceSource: dstIfaceSource,
        dstZone:        dstZone?.name  || null,
        needsWork,
      },
    };
  });
}

// ─── CLI config generator ─────────────────────────────────────────────────────

function generateConfig(selectedPolicies, opts = {}) {
  const {
    defaultSrcIntf = 'port1',
    defaultDstIntf = 'port2',
    natEnabled     = false,
    actionVerb     = 'accept',
    logTraffic     = 'all',
    addresses      = {},
    zones          = {},
  } = opts;

  // Helper: resolve a /32 host — use existing object if found, otherwise suggest a new name
  function resolveHost32(ip, customNames) {
    const cidr = `${ip}/32`;
    const existing = findAddress(cidr, addresses);
    if (existing.found) return { name: existing.name, isNew: false };
    const name = customNames?.[ip] || `FF_HOST_${ip.replace(/\./g, '_')}`;
    return { name, isNew: true };
  }

  const newAddresses  = new Map();  // cidr → name
  const newAddrGroups = new Map();  // grpName → [memberNames]
  const newServices   = new Map();  // "port/proto" → {name, port, proto}
  const policyBlocks  = [];

  for (const p of selectedPolicies) {
    const { analysis } = p;

    // Source address(es) — peut être multiple si policy-grouped merge
    let srcAddrName, srcAddrNames, srcAddrGrpName;
    if (p._use32Src && p.srcHosts && p.srcHosts.length > 0) {
      // Mode /32 : utiliser les hôtes réels plutôt que le subnet /24
      const hostNames = p.srcHosts.map(h => {
        const { name, isNew } = resolveHost32(h, p._srcHostNames);
        if (isNew) newAddresses.set(`${h}/32`, name);
        return name;
      });
      if (hostNames.length === 1) {
        srcAddrName = hostNames[0];
      } else {
        srcAddrGrpName = p._srcAddrName || `FF_HOSTS_${suggestAddrName(p.srcSubnet)}`;
        srcAddrNames = hostNames;
        newAddrGroups.set(srcAddrGrpName, hostNames);
      }
    } else if (p.srcAddrNames && p.srcAddrNames.length > 1) {
      // Multi-src : enregistrer chaque adresse + créer un groupe
      srcAddrNames = p.srcAddrNames;
      const subnets = p.srcSubnets || [p.srcSubnet];
      subnets.forEach((cidr, i) => {
        const name = p.srcAddrNames[i] || suggestAddrName(cidr);
        newAddresses.set(cidr, name);
      });
      // Créer un groupe d'adresses
      srcAddrGrpName = p.srcAddrName || p.policyName || `FF_GRP_${suggestAddrName(subnets[0])}`;
      newAddrGroups.set(srcAddrGrpName, srcAddrNames);
    } else if (p._srcAddrGrpFound) {
      // Groupe existant trouvé → l'utiliser directement
      srcAddrName = p.srcAddrName || p._srcAddrName;
    } else if (analysis.srcAddr.found) {
      srcAddrName = analysis.srcAddr.name;
    } else {
      srcAddrName = p.srcAddrName || analysis.srcAddr.suggestedName;
      newAddresses.set(analysis.srcAddr.cidr, srcAddrName);
    }

    // Destination address
    let dstAddrName;
    if (p._use32Dst && p.dstHosts && p.dstHosts.length > 0) {
      // Mode /32 : utiliser les hôtes réels pour la destination
      const hostNames = p.dstHosts.map(h => {
        const { name, isNew } = resolveHost32(h, p._dstHostNames);
        if (isNew) newAddresses.set(`${h}/32`, name);
        return name;
      });
      if (hostNames.length === 1) {
        dstAddrName = hostNames[0];
      } else {
        const grpName = p._dstAddrName || `FF_HOSTS_${suggestAddrName(p.dstTarget)}`;
        newAddrGroups.set(grpName, hostNames);
        dstAddrName = grpName;
      }
    } else if (analysis.dstAddr.found) {
      dstAddrName = analysis.dstAddr.name;
    } else {
      dstAddrName = p.dstAddrName || analysis.dstAddr.suggestedName;
      if (dstAddrName !== 'all') newAddresses.set(analysis.dstAddr.cidr, dstAddrName);
    }

    // Services
    const serviceNames = [];
    for (const svc of analysis.services) {
      if (svc.found) {
        serviceNames.push(svc.name);
      } else {
        const customName = p.serviceNames?.[svc.label] || svc.suggestedName;
        serviceNames.push(customName);
        if (svc.port) {
          newServices.set(`${svc.port}/${svc.proto}`, {
            name: customName, port: svc.port, proto: svc.proto,
          });
        }
      }
    }
    if (serviceNames.length === 0) serviceNames.push('ALL');

    // Check if services match an existing service group
    const svcGrpMatch = opts.serviceGroups ? findServiceGroup(serviceNames, opts.serviceGroups) : null;
    if (svcGrpMatch) {
      serviceNames.length = 0;
      serviceNames.push(svcGrpMatch.name);
    }

    // Resolve interface name → zone name (belt-and-suspenders: also resolve on server side)
    const _resolveZone = (name) => {
      if (!name) return name;
      for (const z of Object.values(zones)) {
        if (z.members && z.members.includes(name)) return z.name;
      }
      return name;
    };
    const _resolveZoneArr = (v) => Array.isArray(v) ? v.map(_resolveZone) : _resolveZone(v);
    const srcintf  = _resolveZoneArr(p.srcintf  || analysis.srcZone  || analysis.srcIface  || defaultSrcIntf);
    const dstintf  = _resolveZoneArr(p.dstintf  || analysis.dstZone  || analysis.dstIface  || defaultDstIntf);
    const useNat   = p.nat != null ? p.nat : (natEnabled || p.dstType === 'public');

    policyBlocks.push({
      name:        p.policyName || `FF-${String(p.id).padStart(3, '0')}`,
      srcintf, dstintf, srcAddrName: srcAddrGrpName || srcAddrName, srcAddrNames: srcAddrGrpName ? null : srcAddrNames, dstAddrName,
      serviceNames, nat: useNat,
      srcSubnet:   p.srcSubnets ? p.srcSubnets.join(', ') : p.srcSubnet,
      dstTarget:   p.dstTarget,
      serviceDesc: p.serviceDesc, sessions: p.sessions,
      tags: p.tags || [],
    });
  }

  // ── Build CLI output ──
  const L = [];
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  L.push(`# Policies: ${policyBlocks.length}  |  Adresses: ${newAddresses.size}  |  Groupes: ${newAddrGroups.size}  |  Services: ${newServices.size}`);
  L.push('');

  if (newAddresses.size > 0) {
    L.push('# ══════════════════════════════════════════════════');
    L.push('# Nouvelles adresses');
    L.push('# ══════════════════════════════════════════════════');
    L.push('config firewall address');
    for (const [cidr, name] of newAddresses) {
      const [ip, pfxStr] = (cidr || '').split('/');
      const prefix = parseInt(pfxStr, 10) || 32;
      const mask   = cidrToMask(prefix);
      L.push(`    edit "${name}"`);
      L.push(`        set type ipmask`);
      L.push(`        set subnet ${ip} ${mask}`);
      L.push(`    next`);
    }
    L.push('end');
    L.push('');
  }

  if (newAddrGroups.size > 0) {
    L.push('# ══════════════════════════════════════════════════');
    L.push('# Groupes d\'adresses');
    L.push('# ══════════════════════════════════════════════════');
    L.push('config firewall addrgrp');
    for (const [grpName, members] of newAddrGroups) {
      const memberStr = members.map(m => `"${m}"`).join(' ');
      L.push(`    edit "${grpName}"`);
      L.push(`        set member ${memberStr}`);
      L.push(`    next`);
    }
    L.push('end');
    L.push('');
  }

  if (newServices.size > 0) {
    L.push('# ══════════════════════════════════════════════════');
    L.push('# Nouveaux services');
    L.push('# ══════════════════════════════════════════════════');
    L.push('config firewall service custom');
    for (const [, svc] of newServices) {
      const isUdp = /udp/i.test(String(svc.proto));
      L.push(`    edit "${svc.name}"`);
      L.push(`        set protocol TCP/UDP/SCTP`);
      L.push(`        set ${isUdp ? 'udp' : 'tcp'}-portrange ${svc.port}`);
      L.push(`    next`);
    }
    L.push('end');
    L.push('');
  }

  if (policyBlocks.length > 0) {
    L.push('# ══════════════════════════════════════════════════');
    L.push('# Policies');
    L.push('# ══════════════════════════════════════════════════');
    L.push('config firewall policy');
    for (const pol of policyBlocks) {
      const svcStr = pol.serviceNames.map(s => `"${s}"`).join(' ');
      L.push(`    edit 0`);
      L.push(`        set name "${pol.name}"`);
      const srcintfStr = Array.isArray(pol.srcintf)
        ? pol.srcintf.map(i => `"${i}"`).join(' ')
        : `"${pol.srcintf}"`;
      const dstintfStr = Array.isArray(pol.dstintf)
        ? pol.dstintf.map(i => `"${i}"`).join(' ')
        : `"${pol.dstintf}"`;
      L.push(`        set srcintf ${srcintfStr}`);
      L.push(`        set dstintf ${dstintfStr}`);
      const srcAddrStr = pol.srcAddrNames && pol.srcAddrNames.length > 1
        ? pol.srcAddrNames.map(n => `"${n}"`).join(' ')
        : `"${pol.srcAddrName}"`;
      L.push(`        set srcaddr ${srcAddrStr}`);
      L.push(`        set dstaddr "${pol.dstAddrName}"`);
      L.push(`        set service ${svcStr}`);
      L.push(`        set action ${actionVerb}`);
      L.push(`        set schedule "always"`);
      if (pol.nat) L.push(`        set nat enable`);
      L.push(`        set logtraffic ${logTraffic}`);
      if (pol.tags && pol.tags.length > 0) {
        L.push(`        set comments "${pol.tags.join(', ')}"`);
      }
      L.push(`    next`);
    }
    L.push('end');
  }

  return L.join('\n');
}

module.exports = {
  parseFortiConfig,
  analyzePolicies,
  generateConfig,
  validateAgainstExisting,
  findInterfaceForSubnet,
  detectWanCandidates,
  findAddress,
  findAddressGroup,
  findService,
  findServiceGroup,
  PREDEFINED,
};

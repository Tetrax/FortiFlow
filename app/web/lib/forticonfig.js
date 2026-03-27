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
    } else if (t.startsWith('set ') || t.startsWith('append ')) {
      const isAppend = t.startsWith('append ');
      const rest = t.slice(isAppend ? 7 : 4).trim();
      const idx  = rest.indexOf(' ');
      if (idx > 0) {
        const key = rest.slice(0, idx);
        const val = rest.slice(idx + 1).trim().replace(/^"|"$/g, '');
        if (isAppend && editProps[key]) {
          editProps[key] += ' ' + val;
        } else {
          editProps[key] = val;
        }
      } else {
        editProps[rest] = '';
      }
    }
  }

  return results;
}

// ─── Subnet helpers ───────────────────────────────────────────────────────────

function maskBits(mask) {
  const parts = mask.split('.');
  if (parts.length !== 4) return null;
  const n = parts.reduce((acc, o) => (acc * 256) + parseInt(o, 10), 0) >>> 0;
  // Valid subnet mask must be contiguous 1s followed by contiguous 0s
  if (n === 0) return 0;
  const inverted = (~n) >>> 0;
  if ((inverted & (inverted + 1)) !== 0) return null; // not a valid mask
  let bits = 0, v = n;
  while (v) { bits += v & 1; v >>>= 1; }
  return bits;
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
  if (parts.length === 2) {
    const bits = maskBits(parts[1]);
    if (bits === null) return null;
    return `${parts[0]}/${bits}`;
  }
  if (parts.length === 1 && parts[0].includes('/')) return parts[0];
  return null;
}

function parsePorts(portrange) {
  if (!portrange) return [];
  const ports = [];
  for (const part of portrange.trim().split(/\s+/)) {
    const clean = part.split(':')[0]; // strip :src_portrange suffix (FortiGate format)
    let [a, b] = clean.split('-').map(Number);
    if (b && !isNaN(b)) {
      if (a > b) { const t = a; a = b; b = t; }
      for (let i = a; i <= Math.min(b, a + 10000); i++) ports.push(i);
    }
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
 465: { proto: 'tcp', name: 'SMTPS'        },
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
    'antivirus profile',
    'webfilter profile',
    'ips sensor',
    'firewall ssl-ssh-profile',
    'firewall profile-group',
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
    // For iprange: store start/end integers for range matching
    let startInt, endInt;
    if (props['start-ip'] && props['end-ip']) {
      try { startInt = ip2int(props['start-ip']); endInt = ip2int(props['end-ip']); } catch {}
    }
    addresses[name] = { name, type: props.type || 'ipmask', cidr, fqdn: props.fqdn || '', startInt, endInt };
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
  // Post-process: pre-compute expanded CIDRs (recursive, handles nested groups)
  for (const [name, grp] of Object.entries(addressGroups)) {
    grp.expandedCidrs = expandGroupCidrs(grp.members, addressGroups, addresses, new Set([name]));
  }

  // ── Custom services ──
  const customServices = {};
  for (const [name, props] of Object.entries(rawCustomSvcs)) {
    const proto = (props.protocol || 'TCP/UDP/SCTP').toUpperCase();
    const icmptype = props.icmptype !== undefined && props.icmptype !== '' ? parseInt(props.icmptype, 10) : null;
    const icmpcode = props.icmpcode !== undefined && props.icmpcode !== '' ? parseInt(props.icmpcode, 10) : null;
    customServices[name] = {
      name,
      proto,
      tcpPorts: parsePorts(props['tcp-portrange'] || ''),
      udpPorts: parsePorts(props['udp-portrange'] || ''),
      icmptype,
      icmpcode,
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
    if (props.type === 'loopback') continue;
    // Garder les tunnels même si status down (ils existent dans la conf et servent aux policies)
    if (props.status === 'down' && props.type !== 'tunnel') continue;

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
    // WAN : priorité au set role (lan/dmz/undefined = LAN, wan = WAN)
    // puis mode dhcp/pppoe (route par défaut dynamique = WAN)
    // sinon détection par IP (fallback)
    const roleLan  = props.role === 'lan' || props.role === 'dmz';
    const roleWan  = props.role === 'wan';
    const modeDhcp = props.mode === 'dhcp' || props.mode === 'pppoe';
    const isWan = !isTunnel && (roleWan || (!roleLan && (modeDhcp || (!isPrivateIP(props.ip?.split(' ')[0] || '') && !!props.ip))));
    interfaces[name] = {
      name,
      rawIp:    props.ip || '',
      cidr,
      prefix,
      alias:    props.alias || name,
      type:     props.type  || 'physical',
      isWan,
      _roleWan: roleWan,
      isTunnel,
      isSdwan:  sdwanMembers.includes(name),
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

  // Correction isWan par table de routage : les interfaces portant 0.0.0.0/0 sont WAN,
  // les autres sans role wan explicite sont recorrigées en LAN.
  // Si aucune route par défaut → fallback sur détection IP (comportement inchangé).
  const defaultRouteDevices = new Set(
    staticRoutes.filter(r => r.dst === '0.0.0.0/0').map(r => r.device).filter(Boolean)
  );
  if (defaultRouteDevices.size > 0) {
    for (const iface of Object.values(interfaces)) {
      if (iface.isTunnel || iface._roleWan) continue;
      // Les membres SD-WAN sont tous WAN même si un seul porte le 0.0.0.0/0
      if (iface.isSdwan) { iface.isWan = true; continue; }
      iface.isWan = defaultRouteDevices.has(iface.name);
    }
    for (const zone of Object.values(zones)) {
      // Zone WAN si au moins un membre est WAN (SD-WAN = membres mixtes possibles)
      zone.isWan = zone.members.length > 0 && zone.members.some(m => interfaces[m]?.isWan);
    }
  }

  // Table de routes unifiée : statiques + connected (depuis les interfaces)
  const fullRoutes = buildFullRouteTable(staticRoutes, interfaces);

  // Effective SD-WAN interface name to use in policies
  const sdwanIntfName = sdwanEnabled ? (sdwanZoneName || 'virtual-wan-link') : null;

  // VDOM detection (multi-VDOM FortiGate) — parseur partiel, warning UI seulement
  const hasVdom = /^config vdom\s*$/m.test(text);

  // OSPF detection — vérifie la présence de networks configurés
  const hasOspf = /config router ospf[\s\S]*?set router-id\s+\d/m.test(text);

  // ── Security profiles ──
  const securityProfiles = {
    antivirus:    Object.keys(_sections['antivirus profile'] || {}),
    webfilter:    Object.keys(_sections['webfilter profile'] || {}),
    ips:          Object.keys(_sections['ips sensor'] || {}),
    sslSsh:       Object.keys(_sections['firewall ssl-ssh-profile'] || {}),
    profileGroup: Object.keys(_sections['firewall profile-group'] || {}),
  };

  return { addresses, addressGroups, customServices, serviceGroups, interfaces, zones, sdwanMembers, sdwanZoneNames, sdwanEnabled, sdwanIntfName, hasVdom, staticRoutes, fullRoutes, hasBgp, hasOspf, existingPolicies, securityProfiles };
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
    if (pfx <= 0 || pfx > 31) continue; // skip /0, /32 (keep /31 for point-to-point links)
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

// Parse output of: get router info routing-table all
// Handles all route types: C (connected), S (static), O/O IA/O E1/O E2 (OSPF), B (BGP), R (RIP), K (kernel)
// Two line formats:
//   with gateway : "S   10.x.x.x/xx [10/0] via 10.x.x.x, portX"
//   connected    : "C   10.x.x.x/xx is directly connected, portX"
function parseFullRoutingTable(text) {
  const distanceMap = { C: 0, K: 0, S: 1, R: 120, O: 110, B: 20 };
  const routes = [];

  for (const line of text.split('\n')) {
    // Connected routes: "C   10.x.x.x/xx is directly connected, portX"
    const mc = line.match(/^\s*C\s+(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)\s+is directly connected,\s*([^\s,]+)/);
    if (mc) {
      let dst = mc[1];
      if (!dst.includes('/')) dst += '/32';
      routes.push({ dst, gateway: '', device: mc[2], distance: 0, priority: 0, source: 'connected' });
      continue;
    }

    // Routed lines: "[S*|S|O|O IA|O E1|O E2|B|R|K] dst [dist/metric] via gw, dev"
    // Type token may contain spaces (e.g. "O IA", "O E2") — stop at the first digit of the dst IP
    const mr = line.match(/^\s*([A-Z][A-Z0-9* ]*?)\s{2,}(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)\s+\[(\d+)\/\d+\]\s+via\s+([\d.]+),\s*([^\s,]+)/);
    if (mr) {
      let dst = mr[2];
      if (!dst.includes('/')) dst += '/32';
      const typeCode = mr[1].trim().replace(/[* ]/g, '')[0]; // first letter: S, O, B, R, K…
      const distance = parseInt(mr[3], 10);
      const source = ({ S: 'static', O: 'ospf', B: 'bgp', R: 'rip', K: 'kernel' }[typeCode] || 'static');
      routes.push({ dst, gateway: mr[4], device: mr[5], distance, priority: 0, source });
    }
  }

  return routes;

}

// Keep protocol-specific parsers as thin wrappers (backward compat)
function parseOspfRoutingTable(text) {
  return parseFullRoutingTable(text).filter(r => r.source === 'ospf');
}
function parseBgpNetworkTable(text) {
  return parseFullRoutingTable(text).filter(r => r.source === 'bgp');
}

// Longest-prefix match dans la table de routes
// PRE-CONDITION: routes DOIT être trié par préfixe décroissant (via sortRoutes)
// — la première correspondance trouvée est la plus spécifique
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
    if (pfx === 0) continue; // /0 handled in pass 2 (default route)
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
  const rangeMatches = [];
  for (const [name, addr] of Object.entries(addresses)) {
    // Exact CIDR match (highest priority)
    if (addr.cidr === cidr) { matches.push({ name, cidr: addr.cidr, source: 'config' }); continue; }
    if (cidr.endsWith('/32')) {
      const ip = cidr.slice(0, -3);
      if (addr.cidr === ip || addr.cidr === `${ip}/32`) { matches.push({ name, cidr: addr.cidr, source: 'config' }); continue; }
      // IP range matching: check if target IP falls within start-end range
      if (addr.startInt !== undefined && addr.endInt !== undefined) {
        try {
          const targetInt = ip2int(ip);
          if (targetInt >= addr.startInt && targetInt <= addr.endInt) {
            rangeMatches.push({ name, cidr: addr.cidr, source: 'config-range' });
          }
        } catch {}
      }
    }
  }
  // Exact matches take priority over range matches
  const allMatches = matches.length > 0 ? matches : rangeMatches;
  if (allMatches.length === 0) return { found: false };
  return { found: true, name: allMatches[0].name, source: allMatches[0].source, allMatches };
}

// Recursive group expansion with cycle detection
function expandGroupCidrs(memberNames, addressGroups, addresses, visited) {
  const cidrs = [];
  for (const m of memberNames) {
    if (addresses[m]?.cidr) {
      cidrs.push(addresses[m].cidr);
    } else if (addressGroups[m] && !visited.has(m)) {
      visited.add(m);
      cidrs.push(...expandGroupCidrs(addressGroups[m].members, addressGroups, addresses, visited));
    }
  }
  return cidrs;
}

// Cherche un groupe d'adresses existant contenant exactement les CIDRs donnés
function findAddressGroup(cidrs, addressGroups, addresses) {
  if (!cidrs || cidrs.length < 2 || !addressGroups) return null;
  const sortedCidrs = [...cidrs].sort();
  for (const [name, grp] of Object.entries(addressGroups)) {
    const grpCidrs = expandGroupCidrs(grp.members, addressGroups, addresses, new Set([name]))
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

// Match an ICMP/CODE/TYPE label (FortiGate log format) against custom ICMP services
function findIcmpService(label, customServices) {
  const m = label.match(/^ICMP\/(\d+)\/(\d+)$/i);
  if (!m) return null;
  const type = parseInt(m[1], 10), code = parseInt(m[2], 10);
  // Standard ICMP/type/code ordering
  for (const [name, svc] of Object.entries(customServices)) {
    if (svc.proto !== 'ICMP' && svc.proto !== 'ICMP6') continue;
    if (svc.icmptype === null) continue; // ALL_ICMP — skip for specific match
    if (svc.icmptype !== type) continue;
    if (svc.icmpcode !== null && svc.icmpcode !== code) continue;
    return { name, source: 'custom', portHint: `ICMP type ${type} code ${code}` };
  }
  // No specific match → try ALL_ICMP fallback
  for (const [name, svc] of Object.entries(customServices)) {
    if (svc.proto === 'ICMP' && svc.icmptype === null) return { name, source: 'custom', portHint: `ICMP type ${type} code ${code}` };
  }
  return null;
}

// Fuzzy name match: find a service by label similarity (prefix/contains) + observed ports filter
function findServiceByName(label, observedPorts, protoName, customServices) {
  // Never fuzzy-match port-notation labels — they have their own resolution path
  if (/^(TCP|UDP)\/\d+$/i.test(label)) return null;
  const norm = label.toLowerCase().replace(/[-_\s]/g, '');

  // 1. Case-insensitive exact match in custom services
  for (const [name, cs] of Object.entries(customServices)) {
    if (name.toLowerCase() === label.toLowerCase()) {
      const tcp = (cs.tcpPorts || []).slice(0, 8).join(', ');
      const udp = (cs.udpPorts || []).slice(0, 8).join(', ');
      const portHint = [tcp && `TCP: ${tcp}`, udp && `UDP: ${udp}`].filter(Boolean).join(' / ') || null;
      return { found: true, name, source: 'custom', portHint };
    }
  }

  // 2. Prefix match in PREDEFINED names (e.g. "NETBIOS" matches "NetBIOS_NS", "NetBIOS_DS")
  const predefCandidates = [];
  for (const [port, entry] of Object.entries(PREDEFINED)) {
    const en = entry.name.toLowerCase().replace(/[-_\s]/g, '');
    const minLen = Math.max(5, Math.min(norm.length, en.length) - 2);
    if ((en.startsWith(norm) || norm.startsWith(en)) && norm.length >= 5 && en.length >= 5) {
      predefCandidates.push({ port: parseInt(port, 10), proto: entry.proto, name: entry.name });
    }
  }
  if (predefCandidates.length > 0) {
    // Filter by observed ports if available
    const byPort = observedPorts?.length
      ? predefCandidates.filter(c => observedPorts.includes(c.port))
      : predefCandidates;
    const pool = byPort.length > 0 ? byPort : predefCandidates;
    // Accept if all matching entries point to the same root name (e.g. NetBIOS_NS / NetBIOS_DS → "NetBIOS")
    const roots = [...new Set(pool.map(c => c.name.replace(/[-_][A-Z0-9]+$/i, '')))];
    if (roots.length === 1) {
      // Pick the one whose port is most observed, or just the first
      const best = byPort[0] || pool[0];
      const portHint = pool.map(c => `${c.proto.toUpperCase()}: ${c.port}`).join(', ');
      return { found: true, name: best.name, source: 'predefined', portHint };
    }
  }

  // 3. Prefix match in custom service names (min 5 chars)
  for (const [name, cs] of Object.entries(customServices)) {
    const cn = name.toLowerCase().replace(/[-_\s]/g, '');
    if ((cn.startsWith(norm) || norm.startsWith(cn)) && norm.length >= 5 && cn.length >= 5) {
      return { found: true, name, source: 'custom', portHint: null };
    }
  }

  return null;
}

function findService(port, protoName, customServices, opts) {
  const p     = parseInt(port, 10);
  const isUdp = /^(udp|17)$/i.test(String(protoName));
  const maxPortCount = opts?.maxPortCount || Infinity;  // skip services broader than this

  const matches = [];

  // Check predefined
  const predef = findPredefinedService(p, protoName);
  if (predef) matches.push({ name: predef, source: 'predefined', portCount: 1 });

  // Check custom services from config (may be multiple)
  for (const [name, svc] of Object.entries(customServices)) {
    const ports = isUdp ? svc.udpPorts : svc.tcpPorts;
    if (ports.length <= maxPortCount && ports.includes(p)) {
      matches.push({ name, source: 'custom', portCount: ports.length });
    }
  }

  if (matches.length === 0) return { found: false };
  // Prefer most specific match (fewest ports)
  matches.sort((a, b) => a.portCount - b.portCount);
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
        // Try ICMP/CODE/TYPE label matching if not directly found
        const icmpMatch = (!knownPredef && !customMatch) ? findIcmpService(svc, customServices) : null;

        // Fuzzy name match (e.g. "NETBIOS" → "NetBIOS_NS" / "NetBIOS_DS")
        // Skip port-notation labels (e.g. "TCP/853") — they use the port-based fallback path
        const isPortNotationLabel = /^(TCP|UDP)\/\d+$/i.test(svc);
        const fuzzyMatch = (!knownPredef && !customMatch && !icmpMatch && !isPortNotationLabel)
          ? findServiceByName(svc, p.ports, protoLabel, customServices)
          : null;

        // Fallback: if name-based lookup failed, try matching by port against custom services
        let portFallback = null;
        if (!knownPredef && !customMatch && !icmpMatch && !fuzzyMatch) {
          // Port-notation label (e.g. "UDP/11436"): use the port embedded in the label
          const pnm = svc.match(/^(TCP|UDP)\/(\d+)$/i);
          if (pnm) {
            const m = findService(parseInt(pnm[2], 10), pnm[1], customServices, { maxPortCount: 100 });
            if (m.found) portFallback = m;
          } else if (p.ports?.length > 0) {
            // Named service (e.g. "NETBIOS-RPC"): try all observed ports, accept only if
            // all matches resolve to the same service (unambiguous single candidate)
            const candidates = [];
            for (const port of p.ports) {
              const m = findService(port, protoLabel, customServices, { maxPortCount: 5 });
              if (m.found) candidates.push(m);
            }
            const uniqNames = [...new Set(candidates.map(m => m.name))];
            if (uniqNames.length === 1) portFallback = candidates[0];
          }
        }

        // Build port hint for tooltip
        let portHint = '';
        if (icmpMatch) {
          portHint = icmpMatch.portHint;
        } else if (customMatch || portFallback) {
          const cs = customMatch || customServices[portFallback.name];
          if (cs && (cs.proto === 'ICMP' || cs.proto === 'ICMP6')) {
            portHint = cs.icmptype !== null
              ? `${cs.proto} type ${cs.icmptype}${cs.icmpcode !== null ? ` code ${cs.icmpcode}` : ''}`
              : cs.proto;
          } else if (cs) {
            const tcp = cs.tcpPorts.slice(0, 8).join(', ');
            const udp = cs.udpPorts.slice(0, 8).join(', ');
            portHint = [tcp && `TCP: ${tcp}`, udp && `UDP: ${udp}`].filter(Boolean).join(' / ');
          } else if (portFallback) {
            portHint = `${protoLabel}: ${p.ports[0]} (observé)`;
          }
        } else if (fuzzyMatch) {
          portHint = fuzzyMatch.portHint || '';
        } else if (knownPredef) {
          const entries = Object.entries(PREDEFINED).filter(([, e]) => e.name === svc);
          portHint = entries.map(([port, e]) => `${e.proto === 'both' ? 'TCP+UDP' : e.proto.toUpperCase()}: ${port}`).join(', ');
        } else if (p.ports?.length === 1) {
          // Only show observed port when there's exactly one — otherwise it's ambiguous
          portHint = `${protoLabel}: ${p.ports[0]} (observé)`;
        }

        const found = knownPredef || !!customMatch || !!icmpMatch || !!fuzzyMatch || !!portFallback;
        const resolvedName = icmpMatch ? icmpMatch.name
          : fuzzyMatch ? fuzzyMatch.name
          : portFallback ? portFallback.name
          : (knownPredef || customMatch ? svc : null);
        serviceItems.push({
          label: svc,
          found,
          name:  resolvedName,
          source: icmpMatch ? icmpMatch.source : fuzzyMatch ? fuzzyMatch.source : portFallback ? portFallback.source : (knownPredef ? 'predefined' : customMatch ? 'custom' : null),
          suggestedName: resolvedName || svc,
          isNamed: true,
          portHint,
        });
      }
    }
    // Dédupliquer : si un label ICMP/X/Y résout vers le même nom qu'un service nommé explicite, supprimer le doublon
    const seenNames = new Set();
    const deduped = [];
    for (const item of serviceItems) {
      const key = item.name || item.label;
      if (!seenNames.has(key)) { seenNames.add(key); deduped.push(item); }
    }
    serviceItems.length = 0;
    deduped.forEach(i => serviceItems.push(i));

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

    // Auto-detect source interface
    // Priority: 1. srcintf observed in logs (most reliable), 2. route table lookup
    const routes = fortiConfig.fullRoutes || fortiConfig.staticRoutes || [];
    let srcIfaceName   = null;
    let srcIfaceSource = 'auto'; // 'log' | 'route' | 'subnet'
    if (p.flowSrcintf) {
      srcIfaceName   = p.flowSrcintf;
      srcIfaceSource = 'log';
    } else {
      const srcRouteDevice = findInterfaceByRoute(p.srcSubnet, routes, true);
      if (srcRouteDevice) {
        srcIfaceName   = srcRouteDevice;
        srcIfaceSource = 'route';
      }
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

    // Granular status for visual indicators
    const missingFields = [
      ...(!srcAddrMatch.found ? ['srcAddr'] : []),
      ...(!dstAddrMatch.found && p.dstType !== 'public' ? ['dstAddr'] : []),
      ...serviceItems.filter(s => !s.found).map(s => `svc:${s.label}`),
      ...(!srcIfaceName ? ['srcIface'] : []),
      ...(!dstIfaceName ? ['dstIface'] : []),
    ];
    const status = (!srcIfaceName || !dstIfaceName) ? 'error'
      : needsWork ? 'warn' : 'ok';

    // Pré-résoudre les noms d'objets /32 existants pour chaque hôte src/dst
    const srcHostNames = {};
    const srcHostsFound = new Set();
    for (const h of (p.srcHosts || [])) {
      const m = findAddress(`${h}/32`, addresses);
      if (m.found) { srcHostNames[h] = m.name; srcHostsFound.add(h); }
    }
    const dstHostNames = {};
    const dstHostsFound = new Set();
    for (const h of (p.dstHosts || [])) {
      const m = findAddress(`${h}/32`, addresses);
      if (m.found) { dstHostNames[h] = m.name; dstHostsFound.add(h); }
    }

    // Résoudre aussi les hosts dans _multiDstSubnets (round-trip multi-dst)
    if (p._multiDstSubnets) {
      for (const s of p._multiDstSubnets) {
        for (const h of (s.hosts || [])) {
          if (!dstHostNames[h]) {
            const m = findAddress(`${h}/32`, addresses);
            if (m.found) { dstHostNames[h] = m.name; dstHostsFound.add(h); }
          }
        }
        // Réévaluer le match subnet pour chaque sous-groupe
        const subnetMatch = findAddress(s.subnet, addresses);
        if (subnetMatch.found && !s.addrFound) {
          s.addrName  = subnetMatch.name;
          s.addrFound = true;
        }
      }
    }

    return {
      ...p,
      _srcHostNames: Object.keys(srcHostNames).length ? { ...p._srcHostNames, ...srcHostNames } : (p._srcHostNames || undefined),
      _dstHostNames: Object.keys(dstHostNames).length ? { ...p._dstHostNames, ...dstHostNames } : (p._dstHostNames || undefined),
      _srcHostsFound: srcHostsFound.size ? [...srcHostsFound] : (p._srcHostsFound || undefined),
      _dstHostsFound: dstHostsFound.size ? [...dstHostsFound] : (p._dstHostsFound || undefined),
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
        status,
        missingFields,
      },
    };
  });
}

// ─── CLI config generator ─────────────────────────────────────────────────────

// Sanitise une valeur pour insertion dans une commande CLI FortiGate (entre quotes)
function safeCli(str) { return (str || '').replace(/["\\]/g, '_').replace(/[\r\n]/g, ''); }

// Consolidate sorted port numbers into compact range notation for FortiGate CLI
// e.g. [1046,1047,1131,1132,1133] → "1046-1047 1131-1133"
function consolidatePortRanges(ports) {
  if (!ports || ports.length === 0) return '';
  const sorted = [...ports].sort((a, b) => a - b);
  const ranges = [];
  let start = sorted[0], prev = sorted[0];
  for (let i = 1; i <= sorted.length; i++) {
    const cur = sorted[i];
    if (cur === prev + 1) { prev = cur; continue; }
    ranges.push(start === prev ? String(start) : `${start}-${prev}`);
    start = cur; prev = cur;
  }
  return ranges.join(' ');
}

function generateConfig(selectedPolicies, opts = {}) {
  const {
    defaultSrcIntf = 'port1',
    defaultDstIntf = 'port2',
    natEnabled     = false,
    actionVerb     = 'accept',
    logTraffic     = 'all',
    addresses      = {},
    addressGroups  = {},
    zones          = {},
  } = opts;

  // Helper: resolve a /32 host — use existing object if found, otherwise suggest a new name
  function resolveHost32(ip, customNames) {
    const cidr = `${ip}/32`;
    const existing = findAddress(cidr, addresses);
    if (existing.found) return { name: existing.name, isNew: false };
    // Nettoyer le nom si corruption "IP=Nom" stockée par l'ancien import positionnel
    const raw = customNames?.[ip];
    const pfx = ip + '=';
    const cleanedName = raw && raw.startsWith(pfx) ? raw.slice(pfx.length) : raw;
    const name = cleanedName || `FF_HOST_${ip.replace(/\./g, '_')}`;
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
    if (p._multiSrcSubnets?.length > 0) {
      // ── Multi-src subnets : per-subnet /24 vs /32 (like _multiDstSubnets) ──
      const allSrcNames = [];
      for (const s of p._multiSrcSubnets) {
        if (s.useSubnet !== false) {
          // /24 mode: use subnet address
          if (s.addrFound) {
            allSrcNames.push(s.addrName);
          } else {
            const name = s.addrName || suggestAddrName(s.subnet);
            allSrcNames.push(name);
            newAddresses.set(s.subnet, name);
          }
        } else {
          // /32 mode: list individual hosts
          for (const h of (s.hosts || [])) {
            const { name, isNew } = resolveHost32(h, p._srcHostNames);
            if (isNew) newAddresses.set(`${h}/32`, name);
            allSrcNames.push(name);
          }
        }
      }
      srcAddrNames = allSrcNames;
      if (p._useSrcGroup) {
        srcAddrGrpName = p._srcAddrName || `FF_GRP_SRC_${suggestAddrName(p._multiSrcSubnets[0].subnet)}`;
        newAddrGroups.set(srcAddrGrpName, allSrcNames);
      }
    } else if (p._isSvcMerge && p._mergedSrcSubnets && p._mergedSrcSubnets.length > 1) {
      // Fusion par service : créer un groupe d'adresses pour les sources fusionnées
      const subnetNames = p._mergedSrcSubnets.map(s => suggestAddrName(s));
      p._mergedSrcSubnets.forEach((cidr, i) => newAddresses.set(cidr, subnetNames[i]));
      srcAddrGrpName = p._srcAddrName || `FF_SVC_GRP_${suggestAddrName(p._mergedSrcSubnets[0])}`;
      srcAddrNames = subnetNames;
      newAddrGroups.set(srcAddrGrpName, subnetNames);
    } else if (p._use32Src && p.srcHosts && p.srcHosts.length > 0) {
      // Mode /32 : utiliser les hôtes réels plutôt que le subnet /24
      const hostNames = p.srcHosts.map(h => {
        const { name, isNew } = resolveHost32(h, p._srcHostNames);
        if (isNew) newAddresses.set(`${h}/32`, name);
        return name;
      });
      if (hostNames.length === 1) {
        srcAddrName = hostNames[0];
      } else if (p._useSrcGroup) {
        // Utilisateur a demandé un groupe
        srcAddrGrpName = p.srcAddrName || `FF_HOSTS_${suggestAddrName(p.srcSubnet)}`;
        srcAddrNames = hostNames;
        newAddrGroups.set(srcAddrGrpName, hostNames);
      } else {
        // Par défaut : lister inline dans set srcaddr
        srcAddrName = hostNames;
      }
    } else if (p.srcAddrNames && p.srcAddrNames.length > 1 && !p._multiSrcSubnets) {
      // Multi-src legacy : enregistrer chaque adresse + créer un groupe
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
    // ── WAN policy : dstaddr toujours "all" ──
    if (p._isWan || p.dstType === 'public') {
      dstAddrName = 'all';
    // ── Multi-dst policy : destinations diverses avec seuil /24 vs /32 ──
    } else if (p._isMultiDst && p._multiDstSubnets?.length > 0) {
      const dstNames = [];
      for (const s of p._multiDstSubnets) {
        if (s.useSubnet !== false) {
          // /24 mode: use subnet address
          if (s.addrFound) {
            dstNames.push(s.addrName);
          } else {
            const name = s.addrName || suggestAddrName(s.subnet);
            dstNames.push(name);
            newAddresses.set(s.subnet, name);
          }
        } else {
          // /32 mode: list individual hosts
          for (const h of (s.hosts || [])) {
            const { name, isNew } = resolveHost32(h, p._dstHostNames);
            if (isNew) newAddresses.set(`${h}/32`, name);
            dstNames.push(name);
          }
        }
      }
      const uniqueDstNames = [...new Set(dstNames)];
      if (uniqueDstNames.length === 1) {
        dstAddrName = uniqueDstNames[0];
      } else if (uniqueDstNames.length > 1) {
        // Chercher un groupe existant contenant exactement ces membres
        const dstCidrs = uniqueDstNames.map(n => addresses[n]?.cidr || n).filter(Boolean);
        const existingGrp = findAddressGroup(dstCidrs, addressGroups, addresses);
        if (existingGrp) {
          dstAddrName = existingGrp.name;
        } else if (p._useDstGroup) {
          // Utilisateur a demandé un groupe → le créer
          const grpName = p.dstAddrName || `GRP_${(p.policyIds||['0'])[0]}_DST`;
          newAddrGroups.set(grpName, uniqueDstNames);
          dstAddrName = grpName;
        } else {
          // Par défaut : lister inline dans set dstaddr
          dstAddrName = uniqueDstNames;
        }
      }
    } else if (p._use32Dst && p.dstHosts && p.dstHosts.length > 0) {
      // Mode /32 : utiliser les hôtes réels — set dstaddr "h1" "h2" directement, sans groupe
      const hostNames = p.dstHosts.map(h => {
        const { name, isNew } = resolveHost32(h, p._dstHostNames);
        if (isNew) newAddresses.set(`${h}/32`, name);
        return name;
      });
      // On stocke comme tableau pour que le serialiseur génère plusieurs valeurs
      dstAddrName = hostNames.length === 1 ? hostNames[0] : hostNames;
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
        // Si port/proto absents mais label au format TCP/5010 ou UDP/53, les extraire
        let resolvedPort  = svc.port;
        let resolvedProto = svc.proto;
        if (!resolvedPort && !svc.ports?.length && !svc.portRange) {
          const labelMatch = /^(TCP|UDP)\/(\d+)$/i.exec(svc.label || '');
          if (labelMatch) { resolvedProto = labelMatch[1].toUpperCase(); resolvedPort = parseInt(labelMatch[2], 10); }
        }

        if (svc.ports?.length) {
          newServices.set(customName, { name: customName, ports: svc.ports, proto: svc.proto });
        } else if (svc.portRange) {
          newServices.set(customName, { name: customName, portRange: svc.portRange, proto: svc.proto });
        } else if (resolvedPort) {
          newServices.set(`${resolvedPort}/${resolvedProto}`, {
            name: customName, port: resolvedPort, proto: resolvedProto,
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
      name:        p.policyName || '',
      srcintf, dstintf, srcAddrName: srcAddrGrpName || srcAddrName, srcAddrNames: srcAddrGrpName ? null : srcAddrNames, dstAddrName,
      serviceNames, nat: useNat,
      srcSubnet:   p.srcSubnets ? p.srcSubnets.join(', ') : p.srcSubnet,
      dstTarget:   p.dstTarget,
      serviceDesc: p.serviceDesc, sessions: p.sessions,
      tags: p.tags || [],
      disabled:    p._disabled || false,
    });
  }

  // ── Sort policies: most specific first (least permissive → most permissive) ──
  // Criteria (descending specificity):
  //   1. Source prefix length (larger = more specific)
  //   2. Destination prefix length (larger = more specific; "all"/public = 0)
  //   3. Number of services (fewer = more specific)
  const _prefixLen = (cidr) => {
    if (!cidr || cidr === 'all') return 0;
    const m = String(cidr).match(/\/(\d+)/);
    return m ? parseInt(m[1], 10) : 32;
  };
  const _maxPrefix = (subnetStr) => {
    if (!subnetStr) return 0;
    return Math.max(...String(subnetStr).split(',').map(s => _prefixLen(s.trim())));
  };
  policyBlocks.sort((a, b) => {
    const srcDiff = _maxPrefix(b.srcSubnet) - _maxPrefix(a.srcSubnet);
    if (srcDiff !== 0) return srcDiff;
    const dstDiff = _prefixLen(b.dstTarget) - _prefixLen(a.dstTarget);
    if (dstDiff !== 0) return dstDiff;
    return a.serviceNames.length - b.serviceNames.length;
  });

  // ── Build CLI output ──
  const L = [];
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
      L.push(`    edit "${safeCli(name)}"`);
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
      const memberStr = members.map(m => `"${safeCli(m)}"`).join(' ');
      L.push(`    edit "${safeCli(grpName)}"`);
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
      const proto = String(svc.proto).toUpperCase();
      const isUdp = proto === 'UDP' || proto === '17';
      const isTcp = !isUdp;
      const portrangeVal = svc.portRange || (svc.ports?.length ? consolidatePortRanges(svc.ports) : String(svc.port));
      L.push(`    edit "${safeCli(svc.name)}"`);
      L.push(`        set protocol TCP/UDP/SCTP`);
      if (isTcp) L.push(`        set tcp-portrange ${portrangeVal}`);
      if (isUdp) L.push(`        set udp-portrange ${portrangeVal}`);
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
      const svcStr = pol.serviceNames.map(s => `"${safeCli(s)}"`).join(' ');
      L.push(`    edit 0`);
      if (pol.name) L.push(`        set name "${safeCli(pol.name)}"`);
      const srcintfStr = Array.isArray(pol.srcintf)
        ? pol.srcintf.map(i => `"${safeCli(i)}"`).join(' ')
        : `"${safeCli(pol.srcintf)}"`;
      const dstintfStr = Array.isArray(pol.dstintf)
        ? pol.dstintf.map(i => `"${safeCli(i)}"`).join(' ')
        : `"${safeCli(pol.dstintf)}"`;
      L.push(`        set srcintf ${srcintfStr}`);
      L.push(`        set dstintf ${dstintfStr}`);
      const srcAddrStr = pol.srcAddrNames && pol.srcAddrNames.length > 1
        ? pol.srcAddrNames.map(n => `"${safeCli(n)}"`).join(' ')
        : (Array.isArray(pol.srcAddrName)
          ? pol.srcAddrName.map(n => `"${safeCli(n)}"`).join(' ')
          : `"${safeCli(pol.srcAddrName)}"`);
      L.push(`        set srcaddr ${srcAddrStr}`);
      const dstAddrStr = Array.isArray(pol.dstAddrName)
        ? pol.dstAddrName.map(n => `"${safeCli(n)}"`).join(' ')
        : `"${safeCli(pol.dstAddrName)}"`;
      L.push(`        set dstaddr ${dstAddrStr}`);
      L.push(`        set service ${svcStr}`);
      L.push(`        set action ${pol.action || actionVerb}`);
      L.push(`        set schedule "always"`);
      if (pol.disabled) L.push(`        set status disable`);
      if (pol.nat) L.push(`        set nat enable`);
      L.push(`        set logtraffic ${pol.log || logTraffic}`);
      // Security profiles (UTM) — per-policy overrides global
      const sp = Object.assign({}, opts.securityProfiles || {}, pol.securityProfiles || {});
      const hasUtm = sp.antivirus || sp.webfilter || sp.ips || sp.sslSsh || sp.profileGroup;
      if (hasUtm) {
        L.push(`        set utm-status enable`);
        if (sp.profileGroup)  L.push(`        set profile-protocol-options "${safeCli(sp.profileGroup)}"`);
        if (sp.antivirus)     L.push(`        set av-profile "${safeCli(sp.antivirus)}"`);
        if (sp.webfilter)     L.push(`        set webfilter-profile "${safeCli(sp.webfilter)}"`);
        if (sp.ips)           L.push(`        set ips-sensor "${safeCli(sp.ips)}"`);
        if (sp.sslSsh)        L.push(`        set ssl-ssh-profile "${safeCli(sp.sslSsh)}"`);
      }
      if (pol.tags && pol.tags.length > 0) {
        L.push(`        set comments "${safeCli(pol.tags.join(', '))}"`);
      }
      L.push(`    next`);
    }
    L.push('end');
  }

  return L.join('\n');
}

// ─── Preflight validation ─────────────────────────────────────────────────────

function preflightValidation(selectedPolicies, config) {
  const issues = []; // { level: 'warn'|'error', msg }
  const addresses      = config.addresses      || {};
  const addressGroups  = config.addressGroups   || {};
  const interfaces     = config.interfaces      || {};
  const zones          = config.zones           || {};

  const namesUsed = new Map(); // name → [policy indices]

  for (let i = 0; i < selectedPolicies.length; i++) {
    const p = selectedPolicies[i];
    const a = p.analysis || {};
    const label = `Policy #${i + 1}`;

    // Missing interfaces
    const srcIntf = p._srcintf || a.srcIface;
    const dstIntf = p._dstintf || a.dstIface;
    if (!srcIntf) issues.push({ level: 'error', msg: `${label}: interface source manquante` });
    if (!dstIntf) issues.push({ level: 'error', msg: `${label}: interface destination manquante` });
    if (srcIntf && dstIntf && srcIntf === dstIntf) {
      issues.push({ level: 'warn', msg: `${label}: même interface src/dst (${srcIntf}) — hairpin` });
    }

    // Validate interfaces exist in config
    if (srcIntf && !interfaces[srcIntf] && !zones[srcIntf]) {
      issues.push({ level: 'warn', msg: `${label}: interface source "${srcIntf}" absente de la config` });
    }
    if (dstIntf && !interfaces[dstIntf] && !zones[dstIntf]) {
      issues.push({ level: 'warn', msg: `${label}: interface destination "${dstIntf}" absente de la config` });
    }

    // Name collisions with existing objects
    const srcName = p._srcAddrName || a.srcAddr?.name;
    const dstName = p._dstAddrName || a.dstAddr?.name;
    if (srcName && !a.srcAddr?.found) {
      if (addresses[srcName] || addressGroups[srcName]) {
        issues.push({ level: 'error', msg: `${label}: nom addr source "${srcName}" existe déjà avec un CIDR différent` });
      }
    }
    if (dstName && !a.dstAddr?.found) {
      if (addresses[dstName] || addressGroups[dstName]) {
        issues.push({ level: 'error', msg: `${label}: nom addr destination "${dstName}" existe déjà avec un CIDR différent` });
      }
    }

    // Track duplicate policies (same src+dst+svc)
    const svcKey = (a.services || []).map(s => s.name || s.label).sort().join(',');
    const dupKey = `${srcName}|${dstName}|${svcKey}`;
    if (!namesUsed.has(dupKey)) namesUsed.set(dupKey, []);
    namesUsed.get(dupKey).push(i + 1);
  }

  // Detect duplicates
  for (const [, indices] of namesUsed) {
    if (indices.length > 1) {
      issues.push({ level: 'warn', msg: `Policies #${indices.join(', #')} sont des doublons potentiels (mêmes src/dst/services)` });
    }
  }

  // Summary counts
  const errors   = issues.filter(i => i.level === 'error').length;
  const warnings = issues.filter(i => i.level === 'warn').length;
  return { issues, errors, warnings, ok: errors === 0 };
}

function formatExistingPolicies(policies) {
  if (!policies?.length) return '';
  const lines = ['config firewall policy'];
  for (const p of policies) {
    lines.push(`    edit ${p.policyid}`);
    if (p.name)  lines.push(`        set name "${safeCli(p.name)}"`);
    lines.push(`        set srcintf "${(p.srcintf  || []).map(safeCli).join('" "')}"`);
    lines.push(`        set dstintf "${(p.dstintf  || []).map(safeCli).join('" "')}"`);
    lines.push(`        set srcaddr "${(p.srcaddr  || []).map(safeCli).join('" "')}"`);
    lines.push(`        set dstaddr "${(p.dstaddr  || []).map(safeCli).join('" "')}"`);
    lines.push(`        set service "${(p.service  || []).map(safeCli).join('" "')}"`);
    lines.push(`        set action ${p.action || 'accept'}`);
    if (p.nat)                lines.push('        set nat enable');
    if (p.status === 'disable') lines.push('        set status disable');
    lines.push('    next');
  }
  lines.push('end');
  return lines.join('\n');
}

module.exports = {
  parseFortiConfig,
  analyzePolicies,
  generateConfig,
  validateAgainstExisting,
  preflightValidation,
  findInterfaceForSubnet,
  detectWanCandidates,
  findAddress,
  findAddressGroup,
  findService,
  findServiceGroup,
  PREDEFINED,
  parseFullRoutingTable,
  parseOspfRoutingTable,
  parseBgpNetworkTable,
  sortRoutes,
  formatExistingPolicies,
};

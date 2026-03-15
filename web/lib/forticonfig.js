'use strict';

// ─── FortiGate config section parser ─────────────────────────────────────────
// Extrait les blocs : config X / edit "name" / set key val / next / end
// Gère la profondeur pour ignorer les sections imbriquées sans les parser.

function extractSection(lines, sectionName) {
  const result = {};
  let depth     = 0;
  let inTarget  = false;
  let editName  = null;
  let editProps = {};

  for (const rawLine of lines) {
    const t = rawLine.trim();
    if (!t || t.startsWith('#')) continue;

    if (!inTarget) {
      if (t === `config ${sectionName}`) { inTarget = true; depth = 1; }
      continue;
    }

    if (t.startsWith('config ')) { depth++; continue; }
    if (t === 'end') {
      if (--depth === 0) {
        if (editName !== null) result[editName] = editProps;
        break;
      }
      continue;
    }

    if (depth !== 1) continue; // ignorer le contenu des sections imbriquées

    if (t.startsWith('edit ')) {
      if (editName !== null) result[editName] = editProps;
      editName  = t.slice(5).trim().replace(/^"|"$/g, '');
      editProps = {};
    } else if (t === 'next') {
      if (editName !== null) result[editName] = editProps;
      editName = null; editProps = {};
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
  return result;
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

  // ── Raw section extraction ──
  const rawAddresses  = extractSection(lines, 'firewall address');
  const rawCustomSvcs = extractSection(lines, 'firewall service custom');
  const rawInterfaces = extractSection(lines, 'system interface');
  const rawZones      = extractSection(lines, 'system zone');

  // SDWAN : FortiOS 7.x uses "system sdwan", 6.x uses "system virtual-wan-link"
  const sdwanMembers  = parseSdwanMembers(text);
  const sdwanEnabled  = sdwanMembers.length > 0;
  // Virtual interface/zone name used in policies for SD-WAN traffic
  // FortiOS 6.x: "virtual-wan-link", FortiOS 7.x: zone name (often "virtual-wan-link" or custom)
  const sdwanZoneName = (() => {
    if (!sdwanEnabled) return null;
    // 7.x: look for first zone name under system sdwan
    const m = text.match(/config system sdwan[\s\S]*?config zone([\s\S]*?)(?:^\s*end\s*$)/m);
    if (m) {
      const zm = m[1].match(/edit\s+"?([^\s"]+)"?/);
      if (zm) return zm[1];
    }
    // 6.x fallback
    return 'virtual-wan-link';
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
    const isWan = !isPrivateIP(props.ip?.split(' ')[0] || '') && !!props.ip;
    interfaces[name] = {
      name,
      rawIp:  props.ip || '',
      cidr,
      prefix,
      alias:  props.alias || name,
      type:   props.type  || 'physical',
      isWan,
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

  // ── Routes statiques ──
  const staticRoutes = parseStaticRoutes(lines);

  // ── BGP ──
  const bgpNeighborIntfs = parseBgpNeighborIntfs(text);
  const hasBgp = bgpNeighborIntfs.size > 0 || /config router bgp\b/.test(text);

  // Ajouter les voisins BGP comme pseudo-routes /32 (host routes)
  for (const [ip, intf] of bgpNeighborIntfs) {
    staticRoutes.push({ dst: `${ip}/32`, gateway: ip, device: intf, distance: 0, priority: 0 });
  }
  sortRoutes(staticRoutes);

  // Effective SD-WAN interface name to use in policies
  const sdwanIntfName = sdwanEnabled ? (sdwanZoneName || 'virtual-wan-link') : null;

  // VDOM detection (multi-VDOM FortiGate) — parseur partiel, warning UI seulement
  const hasVdom = /^config vdom\s*$/m.test(text);

  return { addresses, customServices, interfaces, zones, sdwanMembers, sdwanEnabled, sdwanIntfName, hasVdom, staticRoutes, hasBgp };
}

// ─── Static routes + BGP parser ──────────────────────────────────────────────

// Extrait config router static → [{dst, device, gateway, distance, priority}]
// Trié par préfixe le plus long d'abord, puis distance croissante
function parseStaticRoutes(lines) {
  const rawRoutes = extractSection(lines, 'router static');
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

// Longest-prefix match dans la table de routes statiques
// Pour la destination dstCidr (IP ou CIDR), retourne le nom de l'interface de sortie
function findInterfaceByRoute(dstCidr, staticRoutes) {
  if (!staticRoutes || staticRoutes.length === 0) return null;
  let targetIp = (dstCidr || '').split('/')[0];
  let targetInt;
  try { targetInt = ip2int(targetIp); } catch { return null; }

  // Passe 1 : routes spécifiques (préfixe > 0)
  for (const route of staticRoutes) {
    if (route.dst === '0.0.0.0/0') continue;
    const [routeIp, pfxStr] = route.dst.split('/');
    const pfx  = parseInt(pfxStr, 10);
    const mask = (0xFFFFFFFF << (32 - pfx)) >>> 0;
    try {
      if ((ip2int(routeIp) & mask) === (targetInt & mask)) return route.device;
    } catch { continue; }
  }

  // Passe 2 : route par défaut
  const def = staticRoutes.find(r => r.dst === '0.0.0.0/0');
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

        serviceItems.push({
          label: svc,
          found: !!(knownPredef || customMatch),
          name:  svc,
          source: knownPredef ? 'predefined' : (customMatch ? 'custom' : null),
          suggestedName: svc,
          isNamed: true,
          portHint,
        });
      }
    } else {
      for (const port of (p.ports || []).slice(0, 10)) {
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

    // Auto-detect interfaces
    const srcIface = findInterfaceForSubnet(p.srcSubnet, interfaces);
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
        const routeDevice = findInterfaceByRoute(p.dstTarget || '0.0.0.0', fortiConfig.staticRoutes);
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
      const routeDevice = findInterfaceByRoute(p.dstTarget, fortiConfig.staticRoutes);
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
    const srcZone = Object.values(zones).find(z => z.members.includes(srcIface?.name)) || null;
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
        srcIface:       srcIface?.name || null,
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
  } = opts;

  const newAddresses = new Map();  // cidr → name
  const newServices  = new Map();  // "port/proto" → {name, port, proto}
  const policyBlocks = [];

  for (const p of selectedPolicies) {
    const { analysis } = p;

    // Source address(es) — peut être multiple si policy-grouped merge
    let srcAddrName, srcAddrNames;
    if (p.srcAddrNames && p.srcAddrNames.length > 1) {
      // Multi-src : enregistrer chaque adresse
      srcAddrNames = p.srcAddrNames;
      const subnets = p.srcSubnets || [p.srcSubnet];
      subnets.forEach((cidr, i) => {
        const name = p.srcAddrNames[i] || suggestAddrName(cidr);
        newAddresses.set(cidr, name);
      });
    } else if (analysis.srcAddr.found) {
      srcAddrName = analysis.srcAddr.name;
    } else {
      srcAddrName = p.srcAddrName || analysis.srcAddr.suggestedName;
      newAddresses.set(analysis.srcAddr.cidr, srcAddrName);
    }

    // Destination address
    let dstAddrName;
    if (analysis.dstAddr.found) {
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

    const srcintf  = p.srcintf  || analysis.srcZone  || analysis.srcIface  || defaultSrcIntf;
    const dstintf  = p.dstintf  || analysis.dstZone  || analysis.dstIface  || defaultDstIntf;
    const useNat   = p.nat != null ? p.nat : (natEnabled || p.dstType === 'public');

    policyBlocks.push({
      name:        p.policyName || `FF-${String(p.id).padStart(3, '0')}`,
      srcintf, dstintf, srcAddrName, srcAddrNames, dstAddrName,
      serviceNames, nat: useNat,
      srcSubnet:   p.srcSubnets ? p.srcSubnets.join(', ') : p.srcSubnet,
      dstTarget:   p.dstTarget,
      serviceDesc: p.serviceDesc, sessions: p.sessions,
    });
  }

  // ── Build CLI output ──
  const L = [];
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  L.push(`# FortiFlow Policy Export — ${ts}`);
  L.push(`# Policies: ${policyBlocks.length}  |  Nouvelles adresses: ${newAddresses.size}  |  Nouveaux services: ${newServices.size}`);
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
      L.push(`        set comment "Created by FortiFlow"`);
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
      L.push(`        set comment "Created by FortiFlow"`);
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
      L.push(`        set srcintf "${pol.srcintf}"`);
      L.push(`        set dstintf "${pol.dstintf}"`);
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
      L.push(`        set comments "FortiFlow: ${pol.srcSubnet} -> ${pol.dstTarget} | ${pol.serviceDesc || ''} | ${pol.sessions || 0} sess"`);
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
  findInterfaceForSubnet,
  detectWanCandidates,
  findAddress,
  findService,
  PREDEFINED,
};

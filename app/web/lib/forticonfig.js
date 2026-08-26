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
        const val = rest.slice(idx + 1).trim();
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

// Réseaux connus par la configuration FortiGate, triés du plus spécifique
// au plus large. Les objets address sont ajoutés avant les interfaces afin
// qu'ils restent prioritaires lorsque le préfixe est identique.
function extractKnownSubnets(fortiConfig) {
  const byCidr = new Map();

  function addCidr(cidr) {
    if (!cidr || !cidr.includes('/')) return;
    const slash = cidr.lastIndexOf('/');
    const ip = cidr.slice(0, slash);
    const prefix = parseInt(cidr.slice(slash + 1), 10);
    const parts = ip.split('.').map(Number);
    if (!Number.isInteger(prefix) || prefix <= 0 || prefix >= 32) return;
    if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return;

    const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
    const networkInt = (ip2int(ip) & mask) >>> 0;
    const normalized = `${int2ip(networkInt)}/${prefix}`;
    if (!byCidr.has(normalized)) {
      byCidr.set(normalized, { prefix, networkInt, cidr: normalized });
    }
  }

  for (const address of Object.values(fortiConfig?.addresses || {})) addCidr(address.cidr);
  for (const iface of Object.values(fortiConfig?.interfaces || {})) addCidr(iface.cidr);

  return [...byCidr.values()].sort((a, b) => b.prefix - a.prefix);
}

function parsePortSpec(portrange) {
  const ports = [];
  const ranges = [];
  if (!portrange) return { ports, ranges };
  for (const part of portrange.trim().split(/\s+/)) {
    const clean = part.split(':')[0]; // strip :src_portrange suffix (FortiGate format)
    if (!/^\d+(?:-\d+)?$/.test(clean)) continue;
    let [start, end = start] = clean.split('-').map(Number);
    if (!Number.isInteger(start) || start < 1 || start > 65535) continue;
    if (!Number.isInteger(end) || end < 1 || end > 65535) continue;
    if (start > end) [start, end] = [end, start];
    ranges.push({ start, end });
    if (start === end) ports.push(start);
  }
  return {
    ports: [...new Set(ports)].sort((a, b) => a - b),
    ranges,
  };
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

function normalizedPort(port) {
  const text = String(port ?? '').trim();
  if (!/^\d+$/.test(text)) return null;
  const parsed = Number(text);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535 ? parsed : null;
}

function findPredefinedService(port, proto) {
  const p = normalizedPort(port);
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

// ─── Multi-VDOM helpers ───────────────────────────────────────────────────────

// Returns the list of VDOM names found in a multi-VDOM config.
// Returns [] if the config is not in multi-VDOM mode.
function extractVdomNames(lines) {
  const names = [];
  let inVdom = false;
  let depth  = 0;
  for (const rawLine of lines) {
    const t = rawLine.trim();
    if (!t || t.startsWith('#')) continue;
    if (!inVdom) {
      if (t === 'config vdom') { inVdom = true; depth = 0; }
      continue;
    }
    // depth 0 inside config vdom = top-level edits (one per VDOM)
    if (depth === 0 && t.startsWith('edit ')) {
      names.push(t.slice(5).trim().replace(/^"|"$/g, ''));
      continue;
    }
    if (t.startsWith('config ')) { depth++; continue; }
    if (t === 'end') { if (depth-- === 0) break; continue; }
  }
  return names;
}

// Extracts the inner lines of a specific VDOM block.
// The result looks like a flat (non-VDOM) FortiGate config and can be
// fed directly to extractSections / parseSdwanMembers / etc.
function extractVdomLines(lines, vdomName) {
  let phase  = 0; // 0: find config vdom, 1: find edit vdomName, 2: collect
  let depth  = 0;
  const result = [];
  for (const rawLine of lines) {
    const t = rawLine.trim();
    if (!t || t.startsWith('#')) continue;
    if (phase === 0) {
      if (t === 'config vdom') { phase = 1; depth = 0; }
      continue;
    }
    if (phase === 1) {
      if (depth === 0 && (t === `edit "${vdomName}"` || t === `edit ${vdomName}`)) {
        phase = 2; depth = 0; continue;
      }
      if (t.startsWith('config ')) { depth++; continue; }
      if (t === 'end') { if (depth-- === 0) break; continue; }
      continue;
    }
    // phase 2: collect
    if (t.startsWith('config ')) { depth++; result.push(rawLine); }
    else if (t === 'end')        { depth--; result.push(rawLine); }
    else if (t === 'next' && depth === 0) break; // end of this VDOM's edit block
    else                         { result.push(rawLine); }
  }
  return result;
}

// ─── Main config parser ───────────────────────────────────────────────────────

function parseFortiConfig(text, selectedVdom = null) {
  const lines = text.split(/\r?\n/);

  // ── Multi-VDOM: if present, extract the target VDOM block and parse it ──
  const vdomList = extractVdomNames(lines);
  let parseLines = lines;
  let parseText  = text;
  let activeVdom = null;
  if (vdomList.length > 0) {
    activeVdom = (selectedVdom && vdomList.includes(selectedVdom)) ? selectedVdom : vdomList[0];
    parseLines = extractVdomLines(lines, activeVdom);
    parseText  = parseLines.join('\n');
  }

  // ── Raw section extraction — single pass for all sections ──
  const _sections     = extractSections(parseLines, [
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
  const sdwanMembers  = parseSdwanMembers(parseText);
  const sdwanEnabled  = sdwanMembers.length > 0;
  // Virtual interface/zone name used in policies for SD-WAN traffic
  // FortiOS 6.x: "virtual-wan-link", FortiOS 7.x: zone name (often "virtual-wan-link" or custom)
  // Parse ALL SDWAN zone names from config system sdwan > config zone
  const sdwanZoneNames = (() => {
    if (!sdwanEnabled) return [];
    const zonesBlock = parseText.match(/config system sdwan[\s\S]*?config zone([\s\S]*?)^\s*end/m);
    if (!zonesBlock) return [];
    const names = [];
    for (const m of zonesBlock[1].matchAll(/edit\s+"?([^\s"]+)"?/g)) names.push(m[1]);
    return names;
  })();
  // Default SDWAN zone: prefer zone that has members assigned (set zone "X" in members)
  const sdwanZoneName = (() => {
    if (!sdwanEnabled) return null;
    const membersBlock = parseText.match(/config system sdwan[\s\S]*?config members([\s\S]*?)^\s*end/m);
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
  const parseIcmpByte = (value) => {
    if (value === undefined || value === '') return null;
    const text = String(value).trim();
    if (!/^\d+$/.test(text)) return NaN;
    const parsed = Number(text);
    return Number.isInteger(parsed) && parsed >= 0 && parsed <= 255 ? parsed : NaN;
  };
  for (const [name, props] of Object.entries(rawCustomSvcs)) {
    const proto = (props.protocol || 'TCP/UDP/SCTP').toUpperCase();
    const icmptype = parseIcmpByte(props.icmptype);
    const icmpcode = parseIcmpByte(props.icmpcode);
    const tcpSpec = parsePortSpec(props['tcp-portrange'] || '');
    const udpSpec = parsePortSpec(props['udp-portrange'] || '');
    const tcpPorts = tcpSpec.ports;
    const udpPorts = udpSpec.ports;
    customServices[name] = {
      name,
      proto,
      tcpPorts,
      udpPorts,
      tcpRanges: tcpSpec.ranges,
      udpRanges: udpSpec.ranges,
      // P1: Sets pré-calculés pour un lookup O(1) dans findService (au lieu de ports.includes O(n))
      _tcpSet: new Set(tcpPorts),
      _udpSet: new Set(udpPorts),
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
  const sdwanMembersBlock = parseText.match(/config system sdwan[\s\S]*?config members([\s\S]*?)^\s*end/m);
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
  const bgpNeighborIntfs = parseBgpNeighborIntfs(parseText);
  // BGP actif seulement si des voisins avec remote-as sont configurés
  const hasBgp = bgpNeighborIntfs.size > 0 || hasBgpNeighbors(parseText);

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

  // OSPF detection — vérifie la présence de networks configurés
  const hasOspf = /config router ospf[\s\S]*?set router-id\s+\d/m.test(parseText);

  // ── Security profiles ──
  const securityProfiles = {
    antivirus:    Object.keys(_sections['antivirus profile'] || {}),
    webfilter:    Object.keys(_sections['webfilter profile'] || {}),
    ips:          Object.keys(_sections['ips sensor'] || {}),
    sslSsh:       Object.keys(_sections['firewall ssl-ssh-profile'] || {}),
    profileGroup: Object.keys(_sections['firewall profile-group'] || {}),
  };

  return { addresses, addressGroups, customServices, serviceGroups, interfaces, zones, sdwanMembers, sdwanZoneNames, sdwanEnabled, sdwanIntfName, vdomList, selectedVdom: activeVdom, hasVdom: vdomList.length > 0, staticRoutes, fullRoutes, hasBgp, hasOspf, existingPolicies, securityProfiles };
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
    // P4: réutiliser le cache expandedCidrs calculé au parse (parseFortiConfig) au lieu de
    // ré-expanser récursivement chaque groupe à chaque appel.
    const grpCidrs = (grp.expandedCidrs || expandGroupCidrs(grp.members, addressGroups, addresses, new Set([name])))
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

function normalizedIcmpProtocol(protoName) {
  const value = String(protoName || '').toUpperCase();
  if (value === '1' || value === 'ICMP') return 'ICMP';
  if (value === '58' || value === 'ICMP6') return 'ICMP6';
  return null;
}

// Match an ICMP/CODE/TYPE label (FortiGate log format) against custom ICMP services.
// A type-only object is broader than a type+code observation and is therefore
// compatible, never exact. Catch-all ICMP objects are not suggested.
function findIcmpService(label, protoName, customServices) {
  const match = String(label || '').match(/^(ICMP6?)\/(\d+)\/(\d+)$/i);
  if (!match) return null;
  const family = match[1].toUpperCase();
  if (normalizedIcmpProtocol(protoName) !== family) return null;
  const type = parseInt(match[2], 10);
  const code = parseInt(match[3], 10);
  if (type < 0 || type > 255 || code < 0 || code > 255) return null;
  const exactMatches = [];
  const compatibleMatches = [];

  for (const [name, service] of Object.entries(customServices || {})) {
    if (service.proto !== family || service.icmptype === null || service.icmptype !== type) continue;
    const exact = service.icmpcode !== null && service.icmpcode === code;
    if (!exact && service.icmpcode !== null) continue;
    const candidate = {
      name,
      source: 'custom',
      proto: family,
      portSpec: exact ? `${family}/${type}/${code}` : `${family}/${type}/*`,
      coverageCount: exact ? 1 : 256,
      extraPortCount: exact ? 0 : 255,
      portHint: exact ? `ICMP type ${type} code ${code}` : `ICMP type ${type} (tous codes)`,
    };
    if (exact) exactMatches.push(candidate);
    else compatibleMatches.push(candidate);
  }

  if (exactMatches.length > 0) {
    exactMatches.sort((a, b) => a.name.localeCompare(b.name));
    const exactMatch = exactMatches[0];
    return {
      found: true,
      name: exactMatch.name,
      source: exactMatch.source,
      portHint: exactMatch.portHint,
      exactMatch,
      allMatches: exactMatches,
    };
  }
  if (compatibleMatches.length > 0) {
    compatibleMatches.sort((a, b) => a.name.localeCompare(b.name));
    return {
      found: false,
      compatibleMatch: compatibleMatches[0],
      compatibleMatches,
      portHint: compatibleMatches[0].portHint,
    };
  }
  return null;
}

function serviceRanges(service, isUdp) {
  const ranges = isUdp ? service.udpRanges : service.tcpRanges;
  if (Array.isArray(ranges)) return ranges;
  const ports = isUdp ? service.udpPorts : service.tcpPorts;
  return (ports || []).map(port => ({ start: port, end: port }));
}

function serviceAllowsTransport(service, proto) {
  const declared = String(service?.proto || '').toUpperCase().split('/');
  return declared.includes(String(proto || '').toUpperCase());
}

function mergedRangeCount(ranges) {
  const sorted = (ranges || [])
    .map(range => ({ start: range.start, end: range.end }))
    .sort((a, b) => a.start - b.start || a.end - b.end);
  let count = 0;
  let current = null;
  for (const range of sorted) {
    if (!current || range.start > current.end + 1) {
      if (current) count += current.end - current.start + 1;
      current = range;
    } else {
      current.end = Math.max(current.end, range.end);
    }
  }
  if (current) count += current.end - current.start + 1;
  return count;
}

function formatRanges(proto, ranges) {
  const values = (ranges || []).map(range => range.start === range.end
    ? String(range.start)
    : `${range.start}-${range.end}`);
  return values.length ? `${proto}/${values.join(',')}` : '';
}

function formatCustomServicePortHint(service) {
  return [
    formatRanges('TCP', serviceRanges(service, false)),
    formatRanges('UDP', serviceRanges(service, true)),
  ].filter(Boolean).join(' / ') || null;
}

function isCatchAllTransportService(name, ranges) {
  const normalizedName = String(name || '').toUpperCase().replace(/[-\s]/g, '_');
  if (normalizedName === 'ALL_TCP' || normalizedName === 'ALL_UDP') return true;
  return mergedRangeCount(ranges) === 65535
    && ranges.some(range => range.start <= 1 && range.end >= 1)
    && ranges.some(range => range.start <= 65535 && range.end >= 65535);
}

function normalizedTransportProtocol(protoName) {
  const value = String(protoName || '').toUpperCase();
  if (value === '6' || value === 'TCP') return 'TCP';
  if (value === '17' || value === 'UDP') return 'UDP';
  return null;
}

function observedTransportNeed(observedPorts, protoName, observedTuples = []) {
  let tuples;
  if (observedTuples.length > 0) {
    tuples = observedTuples.map(tuple => ({
      proto: normalizedTransportProtocol(tuple?.proto),
      port: Number(tuple?.port),
    }));
  } else {
    if (!Array.isArray(observedPorts)) return null;
    const proto = normalizedTransportProtocol(protoName);
    tuples = (observedPorts || []).map(port => {
      const text = String(port).trim();
      return { proto, port: /^\d+$/.test(text) ? Number(text) : NaN };
    });
  }
  if (tuples.some(tuple => !tuple.proto || !Number.isInteger(tuple.port)
      || tuple.port < 1 || tuple.port > 65535)) return null;
  const unique = [...new Map(tuples.map(tuple => [`${tuple.proto}/${tuple.port}`, tuple])).values()]
    .sort((a, b) => a.proto.localeCompare(b.proto) || a.port - b.port);
  const protos = [...new Set(unique.map(tuple => tuple.proto))];
  const ports = [...new Set(unique.map(tuple => tuple.port))].sort((a, b) => a - b);
  return unique.length > 0 ? { proto: protos.length === 1 ? protos[0] : null, ports, tuples: unique } : null;
}

function classifyCustomTransportService(name, service, observedPorts, protoName, observedTuples = []) {
  const need = observedTransportNeed(observedPorts, protoName, observedTuples);
  if (!need || !service || service.proto === 'ICMP' || service.proto === 'ICMP6') return null;
  for (const tuple of need.tuples) {
    if (!serviceAllowsTransport(service, tuple.proto)) return null;
    const ranges = serviceRanges(service, tuple.proto === 'UDP');
    if (ranges.length === 0 || isCatchAllTransportService(name, ranges)
        || !ranges.some(range => tuple.port >= range.start && tuple.port <= range.end)) return null;
  }
  const coverageCount = (serviceAllowsTransport(service, 'TCP')
    ? mergedRangeCount(serviceRanges(service, false)) : 0)
    + (serviceAllowsTransport(service, 'UDP')
      ? mergedRangeCount(serviceRanges(service, true)) : 0);
  const candidate = {
    name,
    source: 'custom',
    proto: need.proto || 'TCP/UDP',
    portSpec: need.proto
      ? formatRanges(need.proto, serviceRanges(service, need.proto === 'UDP'))
      : formatCustomServicePortHint(service),
    coverageCount,
    extraPortCount: Math.max(0, coverageCount - need.tuples.length),
  };
  if (coverageCount === need.tuples.length) {
    return {
      found: true,
      name,
      source: 'custom',
      portHint: formatCustomServicePortHint(service),
      exactMatch: candidate,
      allMatches: [candidate],
    };
  }
  return {
    found: false,
    compatibleMatch: candidate,
    compatibleMatches: [candidate],
    portHint: formatCustomServicePortHint(service),
  };
}

function classifyPredefinedService(name, observedPorts, protoName, observedTuples = []) {
  const need = observedTransportNeed(observedPorts, protoName, observedTuples);
  if (!need) return null;
  const canonical = Object.values(PREDEFINED).find(entry => entry.name.toLowerCase() === String(name).toLowerCase())?.name;
  if (!canonical) return null;
  const coverage = new Set();
  for (const [port, entry] of Object.entries(PREDEFINED)) {
    if (entry.name !== canonical) continue;
    if (entry.proto === 'both') {
      coverage.add(`TCP/${port}`);
      coverage.add(`UDP/${port}`);
    } else {
      coverage.add(`${entry.proto.toUpperCase()}/${port}`);
    }
  }
  const required = need.tuples.map(tuple => `${tuple.proto}/${tuple.port}`);
  if (!required.every(key => coverage.has(key))) return null;
  const candidate = {
    name: canonical,
    source: 'predefined',
    proto: need.proto || 'TCP/UDP',
    portSpec: [...coverage].sort().join(', '),
    coverageCount: coverage.size,
    extraPortCount: Math.max(0, coverage.size - required.length),
  };
  if (coverage.size === required.length) {
    return {
      found: true,
      name: canonical,
      source: 'predefined',
      portHint: candidate.portSpec,
      exactMatch: candidate,
      allMatches: [candidate],
    };
  }
  return {
    found: false,
    compatibleMatch: candidate,
    compatibleMatches: [candidate],
    portHint: candidate.portSpec,
  };
}

function customServiceMatchesPredefined(name, service) {
  const coverage = new Set();
  for (const [port, entry] of Object.entries(PREDEFINED)) {
    if (entry.name.toLowerCase() !== String(name || '').toLowerCase()) continue;
    if (entry.proto === 'both') {
      coverage.add(`TCP/${port}`);
      coverage.add(`UDP/${port}`);
    } else {
      coverage.add(`${entry.proto.toUpperCase()}/${port}`);
    }
  }
  if (coverage.size === 0) return false;
  const configuredCount = mergedRangeCount(serviceRanges(service, false))
    + mergedRangeCount(serviceRanges(service, true));
  if (configuredCount !== coverage.size) return false;
  return [...coverage].every(key => {
    const [proto, portText] = key.split('/');
    if (!serviceAllowsTransport(service, proto)) return false;
    const port = Number(portText);
    return serviceRanges(service, proto === 'UDP')
      .some(range => port >= range.start && port <= range.end);
  });
}

function selectNamedResolution(resolutions) {
  const exact = resolutions.filter(resolution => resolution?.found);
  const exactNames = [...new Set(exact.map(resolution => resolution.name))];
  if (exactNames.length === 1) return exact.find(resolution => resolution.name === exactNames[0]);
  if (exactNames.length > 1) return null;

  const compatibleByName = new Map();
  for (const resolution of resolutions) {
    for (const candidate of (resolution?.compatibleMatches || [])) {
      if (!compatibleByName.has(candidate.name)
          || candidate.extraPortCount < compatibleByName.get(candidate.name).extraPortCount) {
        compatibleByName.set(candidate.name, candidate);
      }
    }
  }
  const compatibleMatches = [...compatibleByName.values()]
    .sort((a, b) => a.extraPortCount - b.extraPortCount || a.name.localeCompare(b.name));
  return compatibleMatches.length > 0
    ? { found: false, compatibleMatch: compatibleMatches[0], compatibleMatches }
    : null;
}

// Name similarity only discovers candidates. Technical protocol/port coverage
// decides whether a candidate is exact, compatible, or unrelated.
function findServiceByName(label, observedPorts, protoName, customServices, observedTuples = []) {
  if (/^(TCP|UDP)\/\d+$/i.test(label)) return null;
  const normalizedLabel = String(label || '').toLowerCase();
  const norm = normalizedLabel.replace(/[-_\s]/g, '');

  const exactCustom = Object.entries(customServices || {})
    .find(([name]) => name.toLowerCase() === normalizedLabel);
  if (exactCustom) {
    const resolution = classifyCustomTransportService(
      exactCustom[0], exactCustom[1], observedPorts, protoName, observedTuples,
    );
    const configuredRanges = [
      ...serviceRanges(exactCustom[1], false),
      ...serviceRanges(exactCustom[1], true),
    ];
    if (observedTuples.length > 0 && resolution?.compatibleMatch
        && configuredRanges.length > 0
        && (configuredRanges.every(range => range.start === range.end)
          || customServiceMatchesPredefined(exactCustom[0], exactCustom[1]))) {
      const exactMatch = {
        ...resolution.compatibleMatch,
        portSpec: formatCustomServicePortHint(exactCustom[1]),
        extraPortCount: 0,
      };
      return {
        found: true,
        name: exactCustom[0],
        source: 'custom',
        portHint: formatCustomServicePortHint(exactCustom[1]),
        exactMatch,
        allMatches: [exactMatch],
        namedObjectMatch: true,
      };
    }
    return resolution;
  }

  const exactPredefined = Object.values(PREDEFINED)
    .find(entry => entry.name.toLowerCase() === normalizedLabel)?.name;
  if (exactPredefined) return classifyPredefinedService(exactPredefined, observedPorts, protoName, observedTuples);

  const resolutions = [];
  const predefinedNames = [...new Set(Object.values(PREDEFINED).map(entry => entry.name))];
  for (const name of predefinedNames) {
    const candidateNorm = name.toLowerCase().replace(/[-_\s]/g, '');
    if ((candidateNorm.startsWith(norm) || norm.startsWith(candidateNorm))
        && norm.length >= 5 && candidateNorm.length >= 5) {
      resolutions.push(classifyPredefinedService(name, observedPorts, protoName, observedTuples));
    }
  }
  for (const [name, service] of Object.entries(customServices || {})) {
    const candidateNorm = name.toLowerCase().replace(/[-_\s]/g, '');
    if ((candidateNorm.startsWith(norm) || norm.startsWith(candidateNorm))
        && norm.length >= 5 && candidateNorm.length >= 5) {
      resolutions.push(classifyCustomTransportService(name, service, observedPorts, protoName, observedTuples));
    }
  }
  return selectNamedResolution(resolutions.filter(Boolean));
}

function findService(port, protoName, customServices, _opts) {
  const p = normalizedPort(port);
  const proto = normalizedTransportProtocol(protoName);
  if (!p || !proto) return { found: false };
  const isUdp = proto === 'UDP';
  const exactMatches = [];
  const compatibleMatches = [];

  // Predefined objects can cover several protocol/port tuples under one name.
  const predef = findPredefinedService(p, protoName);
  const predefinedShadowed = predef && Object.keys(customServices || {})
    .some(name => name.toLowerCase() === predef.toLowerCase());
  if (predef && !predefinedShadowed) {
    const resolution = classifyPredefinedService(predef, [p], proto);
    if (resolution?.found) exactMatches.push(resolution.exactMatch);
    else if (resolution?.compatibleMatch) compatibleMatches.push(resolution.compatibleMatch);
  }

  // Custom services are evaluated from structural ranges, never expanded port arrays.
  for (const [name, svc] of Object.entries(customServices)) {
    if (!serviceAllowsTransport(svc, proto)) continue;
    const ranges = serviceRanges(svc, isUdp);
    if (!ranges.some(range => p >= range.start && p <= range.end)) continue;
    if (isCatchAllTransportService(name, ranges)) continue;

    const relevantCount = mergedRangeCount(ranges);
    const otherProto = isUdp ? 'TCP' : 'UDP';
    const otherCount = serviceAllowsTransport(svc, otherProto)
      ? mergedRangeCount(serviceRanges(svc, !isUdp)) : 0;
    const coverageCount = relevantCount + otherCount;
    const candidate = {
      name, source: 'custom', proto,
      portSpec: formatRanges(proto, ranges),
      coverageCount,
      extraPortCount: Math.max(0, coverageCount - 1),
    };
    if (coverageCount === 1) exactMatches.push(candidate);
    else compatibleMatches.push(candidate);
  }

  if (exactMatches.length > 0) {
    const sourceRank = source => source === 'predefined' ? 0 : 1;
    exactMatches.sort((a, b) => a.coverageCount - b.coverageCount
      || sourceRank(a.source) - sourceRank(b.source)
      || a.name.localeCompare(b.name));
    const exactMatch = exactMatches[0];
    return {
      found: true,
      name: exactMatch.name,
      source: exactMatch.source,
      exactMatch,
      allMatches: exactMatches,
    };
  }
  if (compatibleMatches.length > 0) {
    compatibleMatches.sort((a, b) => a.extraPortCount - b.extraPortCount || a.name.localeCompare(b.name));
    return { found: false, compatibleMatch: compatibleMatches[0], compatibleMatches };
  }
  return { found: false };
}

// ─── Policy analysis ──────────────────────────────────────────────────────────

function suggestAddrName(cidr) {
  return 'FF_' + (cidr || '').replace(/\//g, '_').replace(/\./g, '_');
}

// Recompose des rectangles sûrs source × destination × service à partir des
// policies d'origine. Chaque rectangle correspond uniquement à des tuples
// réellement présents dans _mergedFrom.
function preserveDestinationServiceAffinity(policies) {
  const serviceKey = (svc) => {
    if (typeof svc === 'string') return `label:${svc}`;
    const label = svc?.label || svc?.name || '';
    const transportKeys = serviceTransportKeys(svc).sort();
    if (transportKeys.length > 0) return `label:${label}|keys:${transportKeys.join(',')}`;
    if (svc?.isNamed || label) return `label:${label}`;
    if (svc?.port != null) return `port:${svc.port}/${String(svc.proto || '').toUpperCase()}`;
    if (Array.isArray(svc?.ports)) return `ports:${[...svc.ports].sort((a, b) => a - b).join(',')}/${String(svc.proto || '').toUpperCase()}`;
    return JSON.stringify(svc);
  };

  const serviceLabel = (svc) => typeof svc === 'string' ? svc : (svc?.label || svc?.name || '');

  return (policies || []).flatMap((policy) => {
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return [policy];
    if ((policy.dstTarget === 'all' || policy._dstUseAll === true)
        && policy.dstType !== 'public' && policy._isWan !== true) return [policy];
    if (policy.analysis !== undefined && (!policy.analysis || typeof policy.analysis !== 'object'
        || Array.isArray(policy.analysis) || !Array.isArray(policy.analysis.services)
        || policy.analysis.services.length > 1000
        || policy.analysis.services.some(serviceDecisionMetadataInvalid))) return [policy];
    const malformedBasicScope = ['srcSubnet', 'dstTarget'].some(field =>
      policy[field] !== undefined && (typeof policy[field] !== 'string' || !policy[field]))
      || ['srcHosts', 'dstHosts'].some(field => policy[field] !== undefined
        && (!Array.isArray(policy[field])
          || policy[field].some(host => typeof host !== 'string' || !host)));
    if (malformedBasicScope) return [policy];
    const malformedListScope = ['srcSubnets', 'dstTargets'].some(field =>
      policy[field] !== undefined && (!Array.isArray(policy[field]) || policy[field].some(item => {
        const subnet = typeof item === 'string' ? item : item?.subnet;
        return typeof subnet !== 'string' || !subnet;
      })));
    if (malformedListScope) return [policy];
    if (['srcSubnets', 'dstTargets'].some(field => Array.isArray(policy[field])
        && (policy[field].length === 0 || policy[field].length > 1000
          || new Set(policy[field].map(item => typeof item === 'string' ? item : item?.subnet)).size !== policy[field].length))) return [policy];
    if (['srcHosts', 'dstHosts'].some(field => policy[field]?.length > 1000)) return [policy];
    const malformedMultiScope = ['_multiSrcSubnets', '_multiDstSubnets'].some(field =>
      policy[field] !== undefined && (!Array.isArray(policy[field])
        || policy[field].some(item => !item || typeof item !== 'object'
          || typeof item.subnet !== 'string' || !item.subnet
          || (item.hosts !== undefined && (!Array.isArray(item.hosts)
            || item.hosts.some(host => typeof host !== 'string' || !host))))));
    if (malformedMultiScope) return [policy];
    if (['_multiSrcSubnets', '_multiDstSubnets'].some(field => Array.isArray(policy[field])
        && (policy[field].length === 0 || policy[field].length > 1000
          || new Set(policy[field].map(item => item.subnet)).size !== policy[field].length))) return [policy];
    if (['ports', 'services', 'protos'].some(field => policy[field]?.length > 1000)) return [policy];
    if (policy.srcAddrNames != null) {
      if (!Array.isArray(policy.srcAddrNames) || policy.srcAddrNames.length === 0 || policy.srcAddrNames.length > 1000
          || policy.srcAddrNames.some(name => typeof name !== 'string' || !name)) return [policy];
      const sourceSubnets = Array.isArray(policy._multiSrcSubnets)
        ? policy._multiSrcSubnets.map(item => item.subnet)
        : Array.isArray(policy.srcSubnets)
          ? policy.srcSubnets.map(item => typeof item === 'string' ? item : item?.subnet)
          : [policy.srcSubnet];
      if (policy.srcAddrNames.length !== new Set(sourceSubnets.filter(Boolean)).size) return [policy];
    }
    const affinityProduct = policyAffinityScopeCount(policy, 'src')
      * policyAffinityScopeCount(policy, 'dst')
      * (new Set((policy.analysis?.services || []).flatMap(serviceTransportKeys)).size || 1);
    if (affinityProduct > 100000) return [policy];
    const submittedOrigins = policy._mergedFrom;
    if (submittedOrigins === undefined) return [policy];
    if (!Array.isArray(submittedOrigins) || submittedOrigins.length === 0
        || submittedOrigins.length > 1000
        || submittedOrigins.some(origin => typeof origin?.srcSubnet !== 'string' || !origin.srcSubnet
          || typeof origin?.dstTarget !== 'string' || !origin.dstTarget
          || (origin.action !== undefined && !['accept', 'deny', 'drop'].includes(origin.action))
          || !Array.isArray(origin.analysis?.services) || origin.analysis.services.length === 0
          || origin.analysis.services.length > 1000
          || origin.analysis.services.some(serviceDecisionMetadataInvalid))) {
      return [policy];
    }
    const originActions = new Set(submittedOrigins.map(origin => origin.action).filter(Boolean));
    if (originActions.size > 1) return [policy];
    if (policy.dstType === 'public' && (policy.dstTarget === 'all' || policy._dstUseAll === true)) {
      return [policy];
    }
    const origins = submittedOrigins;
    if (origins.length < 2) return [policy];

    const services = new Map();
    const sourcesByServiceDestination = new Map();
    for (const origin of origins) {
      for (const svc of origin.analysis.services) {
        const key = serviceKey(svc);
        services.set(key, svc);
        if (!sourcesByServiceDestination.has(key)) sourcesByServiceDestination.set(key, new Map());
        const byDestination = sourcesByServiceDestination.get(key);
        if (!byDestination.has(origin.dstTarget)) byDestination.set(origin.dstTarget, new Set());
        byDestination.get(origin.dstTarget).add(origin.srcSubnet);
      }
    }
    const originsByPair = new Map();
    for (const origin of origins) {
      const key = `${origin.srcSubnet}\u0001${origin.dstTarget}`;
      if (!originsByPair.has(key)) originsByPair.set(key, []);
      originsByPair.get(key).push(origin);
    }

    const rectangles = new Map();
    for (const [key, byDestination] of [...sourcesByServiceDestination].sort(([a], [b]) => a.localeCompare(b))) {
      const destinationsBySources = new Map();
      for (const [destination, sourceSet] of [...byDestination].sort(([a], [b]) => a.localeCompare(b))) {
        const sources = [...sourceSet].sort();
        const signature = sources.join('\u0001');
        if (!destinationsBySources.has(signature)) destinationsBySources.set(signature, { sources, destinations: [] });
        destinationsBySources.get(signature).destinations.push(destination);
      }
      for (const group of destinationsBySources.values()) {
        group.destinations.sort();
        const rectangleKey = `${group.sources.join('\u0001')}\u0002${group.destinations.join('\u0001')}`;
        if (!rectangles.has(rectangleKey)) {
          rectangles.set(rectangleKey, { sources: group.sources, destinations: group.destinations, services: new Map() });
        }
        rectangles.get(rectangleKey).services.set(key, services.get(key));
      }
    }

    const sourceMeta = new Map((policy._multiSrcSubnets || []).map(item => [item.subnet, item]));
    const destinationMeta = new Map((policy._multiDstSubnets || []).map(item => [item.subnet, item]));
    if (policy.srcSubnet && !sourceMeta.has(policy.srcSubnet)) {
      sourceMeta.set(policy.srcSubnet, {
        subnet: policy.srcSubnet,
        hosts: policy.srcHosts || [],
        useSubnet: policy._use32Src !== true,
        addrName: policy._srcAddrName || policy.analysis?.srcAddr?.name || '',
        addrFound: !!policy.analysis?.srcAddr?.found,
      });
    }
    if (policy.dstTarget && !destinationMeta.has(policy.dstTarget)) {
      destinationMeta.set(policy.dstTarget, {
        subnet: policy.dstTarget,
        hosts: policy.dstHosts || [],
        useSubnet: policy._use32Dst !== true,
        addrName: policy._dstAddrName || policy.analysis?.dstAddr?.name || '',
        addrFound: !!policy.analysis?.dstAddr?.found,
      });
    }
    const metadata = (items, index) => items.map(subnet => index.get(subnet) || {
      subnet, hosts: [], useSubnet: true, addrName: '', addrFound: false,
    });

    const result = [...rectangles.values()].map(rectangle => {
      const sourceMetadata = metadata(rectangle.sources, sourceMeta);
      const destinationMetadata = metadata(rectangle.destinations, destinationMeta);
      const selectedKeys = new Set(rectangle.services.keys());
      const selectedServices = [...rectangle.services]
        .sort(([a], [b]) => a.localeCompare(b)).map(([, svc]) => svc);
      const transportKeys = [...new Set(selectedServices.flatMap(serviceTransportKeys))].sort();
      const ports = transportKeys
        .filter(key => /^(TCP|UDP)\/\d+$/.test(key))
        .map(key => Number(key.split('/')[1]));
      const protos = [...new Set(transportKeys.map(key => key.split('/')[0]))].sort();
      const selectedOrigins = rectangle.sources.flatMap(source =>
        rectangle.destinations.flatMap(destination =>
          originsByPair.get(`${source}\u0001${destination}`) || []))
        .map(origin => ({
          ...origin,
          analysis: {
            ...origin.analysis,
            services: origin.analysis.services.filter(svc => selectedKeys.has(serviceKey(svc))),
          },
        }))
        .filter(origin => origin.analysis.services.length > 0)
        .sort((a, b) => a.srcSubnet.localeCompare(b.srcSubnet)
          || a.dstTarget.localeCompare(b.dstTarget)
          || a.analysis.services.map(serviceKey).sort().join('\u0001')
            .localeCompare(b.analysis.services.map(serviceKey).sort().join('\u0001')));
      return {
        ...policy,
        srcSubnet: rectangle.sources[0],
        srcSubnets: rectangle.sources,
        _multiSrcSubnets: rectangle.sources.length > 1 ? sourceMetadata : undefined,
        dstTarget: rectangle.destinations[0],
        dstTargets: rectangle.destinations,
        _isMultiDst: rectangle.destinations.length > 1,
        _multiDstSubnets: rectangle.destinations.length > 1 ? destinationMetadata : undefined,
        _dstUseAll: false,
        srcHosts: [...new Set(sourceMetadata.flatMap(item => item.hosts || []))].sort(),
        dstHosts: [...new Set(destinationMetadata.flatMap(item => item.hosts || []))].sort(),
        _use32Src: rectangle.sources.length === 1 && sourceMetadata[0].useSubnet === false,
        _use32Dst: rectangle.destinations.length === 1 && destinationMetadata[0].useSubnet === false,
        services: selectedServices.map(serviceLabel).filter(Boolean),
        ports,
        protos,
        serviceDesc: selectedServices.map(serviceLabel).filter(Boolean).join(', '),
        _mergedCount: selectedOrigins.length,
        _mergedFrom: selectedOrigins,
        _srcAddrName: rectangle.sources.length === 1 && sourceMetadata[0].addrFound ? sourceMetadata[0].addrName : '',
        _srcAddrGrpFound: false,
        _useSrcGroup: false,
        _dstAddrName: rectangle.destinations.length === 1 && destinationMetadata[0].addrFound ? destinationMetadata[0].addrName : '',
        _dstAddrGrpFound: false,
        _useDstGroup: false,
        analysis: {
          ...policy.analysis,
          srcAddr: rectangle.sources.length === 1 ? {
            ...(policy.analysis?.srcAddr || {}),
            found: !!sourceMetadata[0].addrFound,
            name: sourceMetadata[0].addrName || null,
            cidr: rectangle.sources[0],
            suggestedName: sourceMetadata[0].addrName || suggestAddrName(rectangle.sources[0]),
          } : policy.analysis?.srcAddr,
          dstAddr: rectangle.destinations.length === 1 ? {
            ...(policy.analysis?.dstAddr || {}),
            found: !!destinationMetadata[0].addrFound,
            name: destinationMetadata[0].addrName || null,
            cidr: rectangle.destinations[0],
            suggestedName: destinationMetadata[0].addrName || suggestAddrName(rectangle.destinations[0]),
          } : policy.analysis?.dstAddr,
          services: selectedServices,
          needsWork: selectedServices.some(svc => !svc?.found),
        },
      };
    });
    return result.length > 0 ? result : [policy];
  });
}

function analyzePolicies(policies, fortiConfig, preferredWanIntf, observedFlows = []) {
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
    const protoLabel = p.protos?.length === 1 ? p.protos[0] : null;
    const policyTransportNeed = observedTransportNeed(p.ports, protoLabel);
    const portNotationEntries = (p.services || []).map(label =>
      String(label).match(/^(TCP|UDP)\/(\d+)$/i)).filter(Boolean);
    const notationPorts = [...new Set(portNotationEntries.map(match => Number(match[2])))].sort((a, b) => a - b);
    const notationSetMatchesPolicy = !!policyTransportNeed && portNotationEntries.length > 0
      && portNotationEntries.every(match => match[1].toUpperCase() === policyTransportNeed.proto)
      && notationPorts.length === policyTransportNeed.ports.length
      && notationPorts.every((port, index) => port === policyTransportNeed.ports[index]);
    const serviceItems = [];
    const acceptedCompatibleReuse = (keys, compatibleMatches) => {
      if (!keys?.length || !compatibleMatches?.length) return null;
      const requestedNames = keys.map(key => p._serviceReuse?.[key]);
      const requested = requestedNames[0];
      return requested && requestedNames.every(name => name === requested)
        && compatibleMatches.some(match => match.name === requested) ? requested : null;
    };

    if (p.services && p.services.length > 0) {
      for (const svc of p.services) {
        const serviceObservedTuples = observedServiceTuples(p, svc, observedFlows);
        const serviceTransportNeed = observedTransportNeed([], null, serviceObservedTuples);
        const portNotation = svc.match(/^(TCP|UDP)\/(\d+)$/i);
        const icmpNotation = svc.match(/^(ICMP6?)\/(\d+)\/(\d+)$/i);
        const declaredTransportProto = normalizedTransportProtocol(protoLabel);
        const declaredIcmpProto = normalizedIcmpProtocol(protoLabel);
        const observedPortNotationMatches = !!portNotation
          && serviceTransportNeed?.tuples?.length === 1
          && (!declaredTransportProto
            || declaredTransportProto === portNotation[1].toUpperCase())
          && serviceTransportNeed.tuples[0].proto === portNotation[1].toUpperCase()
          && serviceTransportNeed.tuples[0].port === parseInt(portNotation[2], 10);
        const portNotationConsistent = !!portNotation
          && (observedPortNotationMatches
            || (declaredTransportProto === portNotation[1].toUpperCase()
              && notationSetMatchesPolicy));
        const icmpNotationConsistent = !!icmpNotation
          && declaredIcmpProto === icmpNotation[1].toUpperCase();
        const technicalConflict = (portNotation && !portNotationConsistent)
          || (icmpNotation && !icmpNotationConsistent)
          || (!portNotation && !icmpNotation && p.ports?.length > 0
            && !policyTransportNeed && !serviceTransportNeed);
        const icmpResolution = icmpNotationConsistent
          ? findIcmpService(svc, protoLabel, customServices) : null;
        const nameResolution = !portNotation && !icmpNotation && !technicalConflict
          ? findServiceByName(
            svc,
            serviceTransportNeed?.ports || policyTransportNeed?.ports || [],
            serviceTransportNeed?.proto || protoLabel,
            customServices,
            serviceTransportNeed?.tuples || [],
          )
          : null;
        let technicalResolution = portNotationConsistent
          ? findService(parseInt(portNotation[2], 10), portNotation[1], customServices)
          : null;

        const effectiveTransportNeed = serviceTransportNeed || policyTransportNeed;
        if (!portNotation && !icmpNotation && !technicalConflict
            && !nameResolution && effectiveTransportNeed) {
          if (serviceTransportNeed) {
            const predefinedNames = [...new Set(Object.values(PREDEFINED).map(entry => entry.name))];
            technicalResolution = selectNamedResolution([
              ...Object.entries(customServices).map(([name, service]) => classifyCustomTransportService(
                name, service, serviceTransportNeed.ports, serviceTransportNeed.proto,
                serviceTransportNeed.tuples,
              )),
              ...predefinedNames.map(name => classifyPredefinedService(
                name, serviceTransportNeed.ports, serviceTransportNeed.proto,
                serviceTransportNeed.tuples,
              )),
            ].filter(Boolean));
          } else {
            const perPort = policyTransportNeed.ports.map(port => findService(port, protoLabel, customServices));
            const exactNames = perPort.every(resolution => resolution.found)
              ? [...new Set(perPort.map(resolution => resolution.name))]
              : [];
            if (exactNames.length === 1) {
              technicalResolution = perPort[0];
            } else {
              const commonCompatibleNames = perPort.length > 0
                ? (perPort[0].compatibleMatches || []).map(candidate => candidate.name)
                  .filter(name => perPort.slice(1).every(resolution =>
                    (resolution.compatibleMatches || []).some(candidate => candidate.name === name)))
                : [];
              technicalResolution = selectNamedResolution(commonCompatibleNames
                .map(name => customServices[name]
                  ? classifyCustomTransportService(
                    name, customServices[name], policyTransportNeed.ports, protoLabel,
                  )
                  : classifyPredefinedService(name, policyTransportNeed.ports, protoLabel))
                .filter(Boolean));
            }
          }
        }

        const resolution = icmpResolution || nameResolution || technicalResolution;
        const compatibleMatches = resolution?.compatibleMatches || [];
        const observedNeed = portNotationConsistent
          ? { proto: portNotation[1].toUpperCase(), ports: [parseInt(portNotation[2], 10)] }
          : effectiveTransportNeed;
        const singleTransport = observedNeed?.tuples?.length === 1
          ? observedNeed.tuples[0]
          : observedNeed?.ports.length === 1 && observedNeed.proto ? observedNeed : null;
        const decisionKeys = icmpNotationConsistent
          ? [`${icmpNotation[1].toUpperCase()}/${parseInt(icmpNotation[2], 10)}/${parseInt(icmpNotation[3], 10)}`]
          : observedNeed?.tuples
            ? observedNeed.tuples.map(tuple => `${tuple.proto}/${tuple.port}`)
            : observedNeed ? observedNeed.ports.map(port => `${observedNeed.proto}/${port}`) : [];
        const reusedCompatibleName = acceptedCompatibleReuse(decisionKeys, compatibleMatches);
        const found = resolution?.found === true || !!reusedCompatibleName;
        const resolvedName = reusedCompatibleName || (resolution?.found ? resolution.name : null);
        const portHint = resolution?.portHint
          || resolution?.compatibleMatch?.portSpec
          || (singleTransport
            ? `${singleTransport.proto}: ${singleTransport.port ?? singleTransport.ports?.[0]} (observé)`
            : '');
        serviceItems.push({
          label: svc,
          found,
          name:  resolvedName,
          source: reusedCompatibleName ? 'custom-compatible' : (resolution?.found ? resolution.source : null),
          suggestedName: resolvedName || (portNotation ? `FF_SVC_${portNotation[2]}_${portNotation[1].toUpperCase()}` : svc),
          isNamed: true,
          port: singleTransport?.port ?? singleTransport?.ports?.[0],
          proto: icmpNotationConsistent ? icmpNotation[1].toUpperCase() : singleTransport?.proto,
          reuseKeys: decisionKeys.length > 0 ? decisionKeys : undefined,
          technicalConflict: technicalConflict || undefined,
          portHint,
          exactMatch: resolution?.exactMatch || undefined,
          allMatches: resolution?.allMatches || undefined,
          compatibleMatch: resolution?.compatibleMatch || undefined,
          compatibleMatches: compatibleMatches.length > 0 ? compatibleMatches : undefined,
          compatibilityAccepted: reusedCompatibleName ? true : undefined,
          namedObjectMatch: resolution?.namedObjectMatch || undefined,
        });
      }
    }
    // Dédupliquer : si un label ICMP/X/Y résout vers le même nom qu'un service nommé explicite, supprimer le doublon
    const seenNames = new Set();
    const compatibleByName = new Map();
    const deduped = [];
    for (const item of serviceItems) {
      if (item.compatibilityAccepted && item.name) {
        const existing = compatibleByName.get(item.name);
        if (existing) {
          existing.reuseKeys = [...new Set([
            ...serviceTransportKeys(existing), ...serviceTransportKeys(item),
          ])];
          continue;
        }
        compatibleByName.set(item.name, item);
      }
      const key = item.name || item.label;
      if (!seenNames.has(key)) { seenNames.add(key); deduped.push(item); }
    }
    serviceItems.length = 0;
    deduped.forEach(i => serviceItems.push(i));

    // Fallback sur les ports bruts si aucun service nommé reconnu (ou tous ISDB)
    if (serviceItems.length === 0 && policyTransportNeed && !p._mergedServices?.length) {
      for (const port of policyTransportNeed.ports) {
        const match = findService(port, protoLabel, customServices);
        const reuseKey = normalizedTransportProtocol(protoLabel)
          ? `${normalizedTransportProtocol(protoLabel)}/${port}` : '';
        const reusedCompatibleName = acceptedCompatibleReuse(reuseKey ? [reuseKey] : [], match.compatibleMatches);
        serviceItems.push({
          label: `${port}/${protoLabel}`,
          port,
          proto: protoLabel,
          portHint: `${protoLabel}: ${port}`,
          found: match.found || !!reusedCompatibleName,
          name:  match.found ? match.name : reusedCompatibleName,
          source: match.source || (reusedCompatibleName ? 'custom-compatible' : null),
          suggestedName: `FF_SVC_${port}_${protoLabel}`,
          compatibleMatch: match.compatibleMatch || undefined,
          compatibleMatches: match.compatibleMatches || undefined,
          compatibilityAccepted: reusedCompatibleName ? true : undefined,
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

function normalizedFlowProtocol(flow) {
  const value = String(flow?.protoName || flow?.proto || '').toUpperCase();
  if (value === '6' || value === 'TCP') return 'TCP';
  if (value === '17' || value === 'UDP') return 'UDP';
  if (value === '1' || value === 'ICMP') return 'ICMP';
  if (value === '58' || value === 'ICMP6') return 'ICMP6';
  return value;
}

function flowMatchesPolicySide(ip, subnet, policy, multiField, targetsField, hostsField, targetField, useHosts) {
  const multi = policy[multiField];
  if (Array.isArray(multi) && multi.length > 0) {
    return multi.some(item => item?.useSubnet !== false
      ? item?.subnet === subnet
      : (item?.hosts || []).includes(ip));
  }
  const hosts = policy[hostsField];
  if (useHosts) return Array.isArray(hosts) && hosts.includes(ip);
  return policy[targetField] === subnet || policy[targetField] === ip;
}

function flowMatchesPolicyScope(flow, policy) {
  const sourceMatches = flowMatchesPolicySide(
    flow.srcip, flow.srcSubnet, policy,
    '_multiSrcSubnets', 'srcSubnets', 'srcHosts', 'srcSubnet',
    policy._use32Src === true,
  );
  const publicAll = policy.dstType === 'public' && (policy.dstTarget === 'all' || policy._dstUseAll === true);
  const destinationMatches = publicAll
    ? flow.dstType === 'public'
    : flowMatchesPolicySide(
      flow.dstip, flow.dstSubnet, policy,
      '_multiDstSubnets', 'dstTargets', 'dstHosts', 'dstTarget',
      policy._use32Dst === true,
    );
  return sourceMatches && destinationMatches;
}

function policySideElementsProven(policy, evidenceFlows, side) {
  if (side === 'dst' && policy.dstType === 'public'
      && (policy.dstTarget === 'all' || policy._dstUseAll === true)) return evidenceFlows.length > 0;
  const multi = policy[side === 'src' ? '_multiSrcSubnets' : '_multiDstSubnets'];
  const ipField = side === 'src' ? 'srcip' : 'dstip';
  const subnetField = side === 'src' ? 'srcSubnet' : 'dstSubnet';
  if (Array.isArray(multi) && multi.length > 0) {
    return multi.every(item => item?.useSubnet !== false
      ? evidenceFlows.some(flow => flow[subnetField] === item?.subnet)
      : Array.isArray(item?.hosts) && item.hosts.length > 0
        && item.hosts.every(host => evidenceFlows.some(flow => flow[ipField] === host)));
  }
  const useHosts = side === 'src' ? policy._use32Src === true : policy._use32Dst === true;
  if (useHosts) {
    const hosts = policy[side === 'src' ? 'srcHosts' : 'dstHosts'];
    return Array.isArray(hosts) && hosts.length > 0
      && hosts.every(host => evidenceFlows.some(flow => flow[ipField] === host));
  }
  const target = policy[side === 'src' ? 'srcSubnet' : 'dstTarget'];
  return evidenceFlows.some(flow => flow[subnetField] === target || flow[ipField] === target);
}

function policyAffinityScopes(policy, side) {
  const multi = policy[side === 'src' ? '_multiSrcSubnets' : '_multiDstSubnets'];
  let scopes;
  if (Array.isArray(multi) && multi.length > 0) {
    scopes = multi.flatMap(item => item?.useSubnet !== false
      ? [{ subnet: item?.subnet }]
      : (item?.hosts || []).map(host => ({ host })));
  } else {
    const useHosts = policy[side === 'src' ? '_use32Src' : '_use32Dst'] === true;
    scopes = useHosts
      ? (policy[side === 'src' ? 'srcHosts' : 'dstHosts'] || []).map(host => ({ host }))
      : [{ subnet: policy[side === 'src' ? 'srcSubnet' : 'dstTarget'] }];
  }
  return [...new Map(scopes.map(scope => [scope.host ? `h:${scope.host}` : `s:${scope.subnet}`, scope])).values()];
}

function policyAffinityScopeCount(policy, side) {
  const multi = policy[side === 'src' ? '_multiSrcSubnets' : '_multiDstSubnets'];
  if (Array.isArray(multi) && multi.length > 0) {
    return multi.reduce((count, item) => count
      + (item?.useSubnet !== false ? 1 : (Array.isArray(item?.hosts) ? item.hosts.length : 0)), 0);
  }
  const useHosts = policy[side === 'src' ? '_use32Src' : '_use32Dst'] === true;
  return useHosts ? (policy[side === 'src' ? 'srcHosts' : 'dstHosts'] || []).length : 1;
}

function policyAffinityProven(policy, evidenceFlows) {
  const publicAll = policy.dstType === 'public' && (policy.dstTarget === 'all' || policy._dstUseAll === true);
  const sources = policyAffinityScopes(policy, 'src');
  const destinations = publicAll ? [{ publicAll: true }] : policyAffinityScopes(policy, 'dst');
  const serviceKeys = [...new Set((policy.analysis?.services || []).flatMap(serviceTransportKeys))];
  if (sources.length === 0 || destinations.length === 0 || serviceKeys.length === 0) return false;
  const indexScopes = scopes => ({
    hosts: new Map(scopes.filter(scope => scope.host).map(scope => [scope.host, `h:${scope.host}`])),
    subnets: new Map(scopes.filter(scope => scope.subnet).map(scope => [scope.subnet, `s:${scope.subnet}`])),
  });
  const sourceIndex = indexScopes(sources);
  const destinationIndex = indexScopes(destinations);
  const observed = new Set();
  for (const flow of evidenceFlows) {
    const source = sourceIndex.hosts.get(flow.srcip)
      || sourceIndex.subnets.get(flow.srcSubnet) || sourceIndex.subnets.get(flow.srcip);
    const destination = publicAll && flow.dstType === 'public' ? 'p:all'
      : destinationIndex.hosts.get(flow.dstip)
        || destinationIndex.subnets.get(flow.dstSubnet) || destinationIndex.subnets.get(flow.dstip);
    const service = flowServiceTechnicalKey(flow);
    if (source && destination && service) observed.add(`${source}\u0001${destination}\u0001${service}`);
  }
  return sources.every(source => destinations.every(destination => serviceKeys.every(service => {
    const sourceKey = source.host ? `h:${source.host}` : `s:${source.subnet}`;
    const destinationKey = destination.publicAll ? 'p:all'
      : destination.host ? `h:${destination.host}` : `s:${destination.subnet}`;
    return observed.has(`${sourceKey}\u0001${destinationKey}\u0001${service}`);
  })));
}

function publicAllProvenanceProven(policy, observedFlows) {
  const publicAll = policy.dstType === 'public' && (policy.dstTarget === 'all' || policy._dstUseAll === true);
  if (!publicAll || policy._mergedFrom === undefined) return true;
  if (!Array.isArray(policy._mergedFrom) || policy._mergedFrom.length === 0) return false;
  const serviceKeys = [...new Set((policy.analysis?.services || []).flatMap(serviceTransportKeys))];
  if (serviceKeys.length === 0) return false;
  const expectedSources = new Set((policy._multiSrcSubnets?.map(item => item.subnet)
    || policy.srcSubnets || [policy.srcSubnet]).filter(Boolean));
  const originSources = new Set(policy._mergedFrom.map(origin => origin.srcSubnet).filter(Boolean));
  if (expectedSources.size !== originSources.size
      || [...expectedSources].some(source => !originSources.has(source))) return false;
  return policy._mergedFrom.every(origin => origin.dstTarget && origin.dstTarget !== 'all'
    && serviceKeys.every(serviceKey => (observedFlows || []).some(flow =>
      isPolicyEvidenceFlow(flow)
      && flow.dstType === 'public'
      && (flow.srcSubnet === origin.srcSubnet || flow.srcip === origin.srcSubnet)
      && (flow.dstSubnet === origin.dstTarget || flow.dstip === origin.dstTarget)
      && flowServiceTechnicalKey(flow) === serviceKey)));
}

function policyRepresentationIssue(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return 'policy mal formée';
  if (policy.analysis !== undefined && (!policy.analysis || typeof policy.analysis !== 'object'
      || Array.isArray(policy.analysis) || !Array.isArray(policy.analysis.services)
      || policy.analysis.services.length > 1000
      || policy.analysis.services.some(serviceDecisionMetadataInvalid))) return 'analysis.services mal formé';
  for (const field of ['policyName', '_policyName']) {
    if (policy[field] != null && (typeof policy[field] !== 'string' || policy[field].length > 128)) return `${field} mal formé`;
  }
  if (policy.tags != null && (!Array.isArray(policy.tags) || policy.tags.length > 100
      || policy.tags.some(tag => typeof tag !== 'string' || !tag || tag.length > 128))) return 'tags mal formé';
  if (policy.srcAddrNames != null) {
    if (!Array.isArray(policy.srcAddrNames) || policy.srcAddrNames.length > 1000
        || policy.srcAddrNames.some(name => typeof name !== 'string' || !name)) return 'srcAddrNames mal formé';
    if (policy.srcAddrNames.length === 0) return 'srcAddrNames vide';
    const sourceSubnets = Array.isArray(policy._multiSrcSubnets)
      ? policy._multiSrcSubnets.map(item => item?.subnet)
      : Array.isArray(policy.srcSubnets)
        ? policy.srcSubnets.map(item => typeof item === 'string' ? item : item?.subnet)
        : [policy.srcSubnet];
    if (policy.srcAddrNames.length > 0
        && policy.srcAddrNames.length !== new Set(sourceSubnets.filter(Boolean)).size) return 'srcAddrNames désaligné avec les sources';
  }
  for (const field of ['srcSubnet', 'dstTarget']) {
    if (policy[field] !== undefined && (typeof policy[field] !== 'string' || !policy[field])) return `${field} mal formé`;
  }
  for (const field of ['_use32Src', '_use32Dst', '_dstUseAll', '_isWan', '_useSrcGroup', '_useDstGroup', '_isMultiDst']) {
    if (policy[field] !== undefined && typeof policy[field] !== 'boolean') return `${field} mal formé`;
  }
  for (const field of ['srcSubnets', 'dstTargets', 'srcHosts', 'dstHosts']) {
    if (policy[field] !== undefined && !Array.isArray(policy[field])) return `${field} mal formé`;
  }
  for (const field of ['srcHosts', 'dstHosts']) {
    if (Array.isArray(policy[field])
        && policy[field].some(host => typeof host !== 'string' || !host)) return `${field} contient une valeur mal formée`;
    if (Array.isArray(policy[field]) && policy[field].length > 1000) return `${field} trop volumineux`;
  }
  for (const field of ['srcSubnets', 'dstTargets']) {
    if (Array.isArray(policy[field]) && policy[field].some(item => {
      const subnet = typeof item === 'string' ? item : item?.subnet;
      return typeof subnet !== 'string' || !subnet;
    })) return `${field} contient une valeur mal formée`;
    if (Array.isArray(policy[field])) {
      const subnets = policy[field].map(item => typeof item === 'string' ? item : item?.subnet);
      if (new Set(subnets).size !== subnets.length) return `${field} contient un doublon`;
    }
  }
  if (Array.isArray(policy.services)
      && policy.services.some(service => typeof service !== 'string' || !service)) return 'services contient une valeur mal formée';
  for (const field of ['srcSubnets', 'dstTargets']) {
    if (Array.isArray(policy[field]) && policy[field].length === 0) return `${field} vide`;
  }
  if (policy._use32Src === true && (!Array.isArray(policy.srcHosts) || policy.srcHosts.length === 0)) return 'srcHosts vide en mode hôte';
  if (policy._use32Dst === true && (!Array.isArray(policy.dstHosts) || policy.dstHosts.length === 0)) return 'dstHosts vide en mode hôte';
  if (policy._mergedFrom !== undefined) {
    if (!Array.isArray(policy._mergedFrom) || policy._mergedFrom.length === 0
        || policy._mergedFrom.length > 1000) return '_mergedFrom mal formé, vide ou trop volumineux';
    for (const origin of policy._mergedFrom) {
      if (!origin || typeof origin !== 'object'
          || typeof origin.srcSubnet !== 'string' || !origin.srcSubnet
          || typeof origin.dstTarget !== 'string' || !origin.dstTarget
          || (origin.action !== undefined && !['accept', 'deny', 'drop'].includes(origin.action))
          || !Array.isArray(origin.analysis?.services) || origin.analysis.services.length === 0
          || origin.analysis.services.length > 1000
          || origin.analysis.services.some(serviceDecisionMetadataInvalid)) {
        return '_mergedFrom contient une origine mal formée';
      }
    }
    const originActions = new Set(policy._mergedFrom.map(origin => origin.action).filter(Boolean));
    if (originActions.size > 1) {
      return '_mergedFrom contient des actions incohérentes';
    }
    if (policy.dstType === 'public' && (policy.dstTarget === 'all' || policy._dstUseAll === true)) {
      const signaturesBySource = new Map();
      for (const origin of policy._mergedFrom) {
        const signature = [...new Set(origin.analysis.services.flatMap(serviceTransportKeys))].sort().join('\u0001');
        if (!signaturesBySource.has(origin.srcSubnet)) signaturesBySource.set(origin.srcSubnet, new Set());
        signaturesBySource.get(origin.srcSubnet).add(signature);
      }
      if ([...signaturesBySource.values()].some(signatures => signatures.size > 1)) {
        return '_mergedFrom incompatible avec une destination Internet all';
      }
    }
  }
  for (const field of ['_multiSrcSubnets', '_multiDstSubnets']) {
    if (policy[field] !== undefined && !Array.isArray(policy[field])) return `${field} mal formé`;
    if (Array.isArray(policy[field]) && policy[field].length === 0) return `${field} vide`;
    if (Array.isArray(policy[field]) && policy[field].length > 1000) return `${field} trop volumineux`;
    const seenSubnets = new Set();
    for (const item of (policy[field] || [])) {
      if (!item || typeof item !== 'object' || typeof item.useSubnet !== 'boolean') return `${field}.useSubnet mal formé`;
      if (typeof item.subnet !== 'string' || !item.subnet || seenSubnets.has(item.subnet)) return `${field}.subnet dupliqué ou absent`;
      seenSubnets.add(item.subnet);
      if (item.addrFound !== undefined && typeof item.addrFound !== 'boolean') return `${field}.addrFound mal formé`;
      if (item.hosts !== undefined && !Array.isArray(item.hosts)) return `${field}.hosts mal formé`;
      if (Array.isArray(item.hosts) && item.hosts.length > 1000) return `${field}.hosts trop volumineux`;
      if (Array.isArray(item.hosts)
          && item.hosts.some(host => typeof host !== 'string' || !host)) return `${field}.hosts contient une valeur mal formée`;
      if (item.useSubnet === false && (!Array.isArray(item.hosts) || item.hosts.length === 0)) return `${field}.hosts vide en mode hôte`;
      if (item.addrName !== undefined && typeof item.addrName !== 'string') return `${field}.addrName mal formé`;
    }
    const hostFlag = field === '_multiSrcSubnets' ? '_use32Src' : '_use32Dst';
    if (policy[field]?.length && policy[hostFlag] === true) return `${field} incohérent avec ${hostFlag}`;
  }
  for (const [listField, multiField] of [
    ['srcSubnets', '_multiSrcSubnets'],
    ['dstTargets', '_multiDstSubnets'],
  ]) {
    if (!Array.isArray(policy[listField]) || !Array.isArray(policy[multiField])) continue;
    const aliases = new Set(policy[listField].map(item => typeof item === 'string' ? item : item?.subnet));
    const scoped = new Set(policy[multiField].map(item => item.subnet));
    if (aliases.size !== scoped.size || [...aliases].some(subnet => !scoped.has(subnet))) {
      return `${listField}/${multiField} incohérents`;
    }
  }
  if (policy._isWan === true && policy.dstType !== 'public') return '_isWan incohérent avec le type destination';
  if (!policy._multiSrcSubnets?.length && policy.srcSubnets?.length
      && (policy.srcSubnets.length !== 1 || (policy.srcSubnets[0]?.subnet || policy.srcSubnets[0]) !== policy.srcSubnet)) {
    return 'srcSubnet/srcSubnets incohérents';
  }
  if (!policy._multiDstSubnets?.length && policy.dstTargets?.length
      && (policy.dstTargets.length !== 1 || (policy.dstTargets[0]?.subnet || policy.dstTargets[0]) !== policy.dstTarget)) {
    return 'dstTarget/dstTargets incohérents';
  }
  if (!policy._multiSrcSubnets?.length && policy._srcMode === 'hosts' && policy._use32Src !== true) return 'mode source hosts incohérent';
  if (!policy._multiSrcSubnets?.length && policy._srcMode === 'subnet' && policy._use32Src === true) return 'mode source subnet incohérent';
  if (!policy._multiDstSubnets?.length && policy._dstMode === 'hosts' && policy._use32Dst !== true) return 'mode destination hosts incohérent';
  if (!policy._multiDstSubnets?.length && policy._dstMode === 'subnet' && policy._use32Dst === true) return 'mode destination subnet incohérent';
  for (const field of ['ports', 'services', 'protos']) {
    if (Array.isArray(policy[field]) && policy[field].length > 1000) return `${field} trop volumineux`;
  }
  if ((policy.dstTarget === 'all' || policy._dstUseAll === true)
      && policy.dstType !== 'public' && policy._isWan !== true) return 'destination all interdite hors WAN';
  if (policy.dstTarget === 'all' && policy._dstUseAll !== true) return 'destination all non confirmée';
  if (policy.dstTarget !== 'all' && policy._dstUseAll === true) return 'destination spécifique marquée all';
  const sourceScopes = policyAffinityScopeCount(policy, 'src');
  const destinationScopes = policyAffinityScopeCount(policy, 'dst');
  if (sourceScopes > 10000 || destinationScopes > 10000) return 'cardinalité de scope trop volumineuse';
  const serviceScopes = new Set((policy.analysis?.services || []).flatMap(serviceTransportKeys)).size || 1;
  if (sourceScopes * destinationScopes * serviceScopes > 100000) return 'produit d’affinité trop volumineux';
  return null;
}

function validatePolicyDecisionShapes(policies) {
  const issues = [];
  if (!Array.isArray(policies)) {
    return { ok: false, issues: [{ level: 'error', code: 'SCOPE_DECISION_INVALID', msg: 'Policies mal formées' }] };
  }
  policies.forEach((policy, index) => {
    const candidate = policy;
    const malformedServiceField = candidate && typeof candidate === 'object' && !Array.isArray(candidate)
      ? ['ports', 'services', 'protos']
        .find(field => candidate[field] !== undefined && !Array.isArray(candidate[field]))
      : null;
    const issue = malformedServiceField
      ? `${malformedServiceField} mal formé`
      : policyRepresentationIssue(candidate);
    if (issue) issues.push({ level: 'error', code: 'SCOPE_DECISION_INVALID', msg: `Policy #${index + 1}: ${issue}` });
  });
  return { ok: issues.length === 0, issues };
}

function isPolicyEvidenceFlow(flow) {
  return [
    'accept', 'allow', 'allowed', 'pass', 'start',
    'close', 'timeout', 'client-rst', 'server-rst', 'ip-conn',
    'deny', 'denied', 'drop', 'dropped', 'block', 'blocked',
    'reject', 'rejected', 'violation',
  ].includes(String(flow?.action || '').toLowerCase());
}

function observedServiceTuples(policy, serviceLabel, observedFlows) {
  const tuples = new Map();
  for (const flow of (observedFlows || [])) {
    if (!isPolicyEvidenceFlow(flow) || !flowMatchesPolicyScope(flow, policy)) continue;
    if (String(flow.service || '').toUpperCase() !== String(serviceLabel || '').toUpperCase()) continue;
    const port = Number(flow.dstport);
    const proto = normalizedFlowProtocol(flow);
    if (!Number.isInteger(port) || port < 1 || port > 65535 || !['TCP', 'UDP'].includes(proto)) continue;
    tuples.set(`${proto}/${port}`, { proto, port });
  }
  return [...tuples.values()];
}

function serviceNameDecisionIssue(name, fortiConfig) {
  const reserved = new Set(['ALL', 'ALL_TCP', 'ALL_UDP', 'ALL_ICMP', 'ALL_ICMP6']);
  if (!name || name.length > 79 || reserved.has(name.toUpperCase())
      || /["\\?*#\u0000-\u001f\u007f]/.test(name)) {
    return { code: 'SERVICE_NAME_INVALID', msg: `nom de service invalide "${name}"` };
  }
  const existingName = Object.keys(fortiConfig?.customServices || {})
    .find(candidate => candidate.toLowerCase() === name.toLowerCase());
  const existingGroup = Object.keys(fortiConfig?.serviceGroups || {})
    .find(candidate => candidate.toLowerCase() === name.toLowerCase());
  const predefinedName = Object.values(PREDEFINED)
    .some(service => service.name.toLowerCase() === name.toLowerCase());
  if (existingName || existingGroup || predefinedName) {
    return { code: 'SERVICE_NAME_CONFLICT', msg: `nom de service déjà utilisé "${name}"` };
  }
  return null;
}

function serviceTransportKey(service) {
  const icmp = String(service?.label || '').match(/^(ICMP6?)\/(\d+)\/(\d+)$/i);
  if (icmp) return `${icmp[1].toUpperCase()}/${parseInt(icmp[2], 10)}/${parseInt(icmp[3], 10)}`;
  const notation = String(service?.label || '').match(/^(TCP|UDP)\/(\d+)$/i);
  const proto = String(notation ? notation[1] : service?.proto || '').toUpperCase();
  const port = Number(notation ? notation[2] : service?.port);
  return ['TCP', 'UDP'].includes(proto) && Number.isInteger(port) && port >= 1 && port <= 65535
    ? `${proto}/${port}`
    : '';
}

function serviceDecisionMetadataInvalid(service) {
  if (!service || typeof service !== 'object' || Array.isArray(service)
      || ![service.label, service.name].some(value => typeof value === 'string' && value.trim())) return true;
  for (const field of ['reuseKeys', 'ports', 'sourcePorts', 'tcpPorts', 'udpPorts', 'tcpRanges', 'udpRanges', 'compatibleMatches', 'allMatches']) {
    if (service[field] !== undefined && (!Array.isArray(service[field]) || service[field].length > 1000)) return true;
  }
  if (service.reuseKeys?.some(key => typeof key !== 'string' || !key.trim())) return true;
  for (const field of ['ports', 'sourcePorts', 'tcpPorts', 'udpPorts']) {
    if (service[field]?.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) return true;
  }
  for (const field of ['tcpRanges', 'udpRanges']) {
    if (service[field]?.some(range => !range || typeof range !== 'object' || Array.isArray(range)
      || !Number.isInteger(range.start) || !Number.isInteger(range.end)
      || range.start < 1 || range.end > 65535 || range.start > range.end)) return true;
  }
  for (const field of ['compatibleMatches', 'allMatches']) {
    if (service[field]?.some(match => !match || typeof match !== 'object' || Array.isArray(match)
      || typeof match.name !== 'string' || !match.name.trim())) return true;
  }
  return false;
}

function serviceTransportKeys(service) {
  if (Array.isArray(service?.reuseKeys)) {
    return [...new Set(service.reuseKeys.map(key => String(key).toUpperCase()).filter(Boolean))];
  }
  const proto = String(service?.proto || '').toUpperCase();
  const ports = Array.isArray(service?.sourcePorts) ? service.sourcePorts : service?.ports;
  if (['TCP', 'UDP'].includes(proto) && Array.isArray(ports)) {
    return [...new Set(ports.map(Number)
      .filter(port => Number.isInteger(port) && port >= 1 && port <= 65535)
      .map(port => `${proto}/${port}`))];
  }
  const key = serviceTransportKey(service);
  return key ? [key] : [];
}

function flowServiceTechnicalKey(flow) {
  const icmp = String(flow?.service || '').match(/^(ICMP6?)\/(\d+)\/(\d+)$/i);
  if (icmp && normalizedIcmpProtocol(normalizedFlowProtocol(flow)) === icmp[1].toUpperCase()) {
    return `${icmp[1].toUpperCase()}/${parseInt(icmp[2], 10)}/${parseInt(icmp[3], 10)}`;
  }
  const proto = normalizedFlowProtocol(flow);
  const port = Number(flow?.dstport);
  return ['TCP', 'UDP'].includes(proto) && Number.isInteger(port)
    ? `${proto}/${port}`
    : '';
}

function serviceEvidenceProven(service, evidenceFlows) {
  if (service?.technicalConflict) return false;
  const label = String(service?.label || '').toUpperCase();
  const forward = label.match(/^(TCP|UDP)\/(\d+)$/);
  const reverse = label.match(/^(\d+)\/(TCP|UDP)$/);
  const notation = forward
    ? { proto: forward[1], port: Number(forward[2]) }
    : reverse ? { proto: reverse[2], port: Number(reverse[1]) } : null;
  if (!notation) {
    const transportKeys = serviceTransportKeys(service);
    return evidenceFlows.some(flow => {
      if (String(flow.service || '').toUpperCase() !== label) return false;
      return transportKeys.length === 0
        || transportKeys.includes(flowServiceTechnicalKey(flow));
    });
  }
  const expectedProto = notation.proto;
  const expectedPort = notation.port;
  const acceptedLabels = new Set([`${expectedProto}/${expectedPort}`, `${expectedPort}/${expectedProto}`]);
  return evidenceFlows.some(flow => {
    const flowLabel = String(flow.service || '').toUpperCase();
    return normalizedFlowProtocol(flow) === expectedProto
      && Number(flow.dstport) === expectedPort
      && (!flowLabel || acceptedLabels.has(flowLabel));
  });
}

function foundServiceEvidenceProven(service, evidenceFlows, fortiConfig) {
  const selectedKeys = serviceTransportKeys(service);
  const relevant = evidenceFlows.filter(flow => service.compatibilityAccepted === true
    ? selectedKeys.includes(flowServiceTechnicalKey(flow))
    : String(flow.service || '').toUpperCase() === String(service.label || '').toUpperCase());
  if (relevant.length === 0) return false;
  if (service.compatibilityAccepted === true
      && !selectedKeys.every(key => relevant.some(flow => flowServiceTechnicalKey(flow) === key))) {
    return false;
  }
  const custom = fortiConfig?.customServices?.[service.name];
  if (custom?.proto === 'ICMP' || custom?.proto === 'ICMP6') {
    return relevant.every(flow => {
      const resolution = findIcmpService(
        flow.service, normalizedFlowProtocol(flow), fortiConfig?.customServices || {},
      );
      if (service.compatibilityAccepted === true) {
        return (resolution?.compatibleMatches || []).some(candidate => candidate.name === service.name);
      }
      return resolution?.found === true && resolution.name === service.name;
    });
  }

  const transportKeys = new Set();
  const covered = relevant.every(flow => {
    const proto = normalizedFlowProtocol(flow);
    const port = Number(flow.dstport);
    if (!['TCP', 'UDP'].includes(proto) || !Number.isInteger(port)) return false;
    transportKeys.add(`${proto}/${port}`);
    if (custom) {
      if (!serviceAllowsTransport(custom, proto)) return false;
      const ports = proto === 'TCP' ? (custom.tcpPorts || []) : (custom.udpPorts || []);
      const ranges = proto === 'TCP' ? (custom.tcpRanges || []) : (custom.udpRanges || []);
      return ports.includes(port) || ranges.some(range => port >= range.start && port <= range.end);
    }
    return Object.entries(PREDEFINED).some(([definedPort, definition]) =>
      definition.name === service.name
      && Number(definedPort) === port
      && (definition.proto === 'both' || definition.proto.toUpperCase() === proto)
    );
  });
  if (!covered || service.compatibilityAccepted === true) return covered;
  if (!custom) {
    return !service.exactMatch?.coverageCount
      || service.exactMatch.coverageCount === transportKeys.size;
  }
  if (service.namedObjectMatch === true) {
    const configuredRanges = [
      ...serviceRanges(custom, false),
      ...serviceRanges(custom, true),
    ];
    return configuredRanges.length > 0
      && (configuredRanges.every(range => range.start === range.end)
        || customServiceMatchesPredefined(service.name, custom));
  }
  const coverageCount = (serviceAllowsTransport(custom, 'TCP')
    ? mergedRangeCount(serviceRanges(custom, false)) : 0)
    + (serviceAllowsTransport(custom, 'UDP')
      ? mergedRangeCount(serviceRanges(custom, true)) : 0);
  return coverageCount === transportKeys.size;
}

function observedPolicyTransportKeys(policy, observedFlows) {
  const keys = new Set();
  for (const flow of (observedFlows || [])) {
    if (!isPolicyEvidenceFlow(flow) || !flowMatchesPolicyScope(flow, policy)) continue;
    const proto = normalizedFlowProtocol(flow);
    const port = Number(flow.dstport);
    if (['TCP', 'UDP'].includes(proto) && Number.isInteger(port) && port >= 1 && port <= 65535) {
      keys.add(`${proto}/${port}`);
    }
  }
  return keys;
}

function validateGenerationOptions(input, fortiConfig) {
  const issues = [];
  const validShape = input == null || (typeof input === 'object' && !Array.isArray(input));
  if (!validShape) {
    issues.push({ level: 'error', code: 'OPTIONS_DECISION_INVALID', msg: 'Options globales mal formées' });
  }
  const source = validShape && input ? input : {};
  const action = String(source.action ?? 'accept').toLowerCase();
  const log = String(source.log ?? 'all').toLowerCase();
  if (!['accept', 'deny'].includes(action)) {
    issues.push({ level: 'error', code: 'ACTION_DECISION_INVALID', msg: `Action globale invalide "${source.action}"` });
  }
  if (!['all', 'utm', 'disable'].includes(log)) {
    issues.push({ level: 'error', code: 'LOG_DECISION_INVALID', msg: `Mode de log global invalide "${source.log}"` });
  }
  if (source.nat !== undefined && typeof source.nat !== 'boolean') {
    issues.push({ level: 'error', code: 'NAT_DECISION_INVALID', msg: 'Décision NAT globale invalide' });
  }
  const securityProfiles = {};
  if (source.securityProfiles !== undefined) {
    if (!source.securityProfiles || typeof source.securityProfiles !== 'object' || Array.isArray(source.securityProfiles)) {
      issues.push({ level: 'error', code: 'SECURITY_PROFILE_DECISION_INVALID', msg: 'Profils de sécurité globaux invalides' });
    } else {
      for (const [key, name] of Object.entries(source.securityProfiles)) {
        if (!['antivirus', 'webfilter', 'ips', 'sslSsh', 'profileGroup'].includes(key)
            || !(fortiConfig?.securityProfiles?.[key] || []).includes(name)) {
          issues.push({ level: 'error', code: 'SECURITY_PROFILE_DECISION_INVALID', msg: `Profil global ${key} inconnu "${name}"` });
        } else {
          securityProfiles[key] = name;
        }
      }
    }
  }
  const wanOverrides = [];
  if (source.wanOverrides !== undefined && !Array.isArray(source.wanOverrides)) {
    issues.push({ level: 'error', code: 'WAN_DECISION_INVALID', msg: 'Overrides WAN invalides' });
  } else {
    for (const name of (source.wanOverrides || [])) {
      if (typeof name !== 'string' || !fortiConfig?.interfaces?.[name]) {
        issues.push({ level: 'error', code: 'WAN_DECISION_INVALID', msg: `Override WAN inconnu "${name}"` });
      } else if (!wanOverrides.includes(name)) {
        wanOverrides.push(name);
      }
    }
  }
  const validWanNames = new Set([
    ...Object.values(fortiConfig?.interfaces || {}).filter(iface => iface.isWan).map(iface => iface.name),
    ...Object.values(fortiConfig?.zones || {}).filter(zone => zone.isWan).map(zone => zone.name),
    ...(fortiConfig?.sdwanZoneNames || []),
    fortiConfig?.sdwanIntfName,
    ...wanOverrides,
  ].filter(Boolean));
  const preferredWanIntf = source.preferredWanIntf || null;
  if (preferredWanIntf !== null
      && (typeof preferredWanIntf !== 'string' || !validWanNames.has(preferredWanIntf))) {
    issues.push({ level: 'error', code: 'WAN_DECISION_INVALID', msg: `Interface WAN préférée invalide "${preferredWanIntf}"` });
  }
  return {
    ok: issues.length === 0,
    issues,
    opts: {
      action: ['accept', 'deny'].includes(action) ? action : 'accept',
      log: ['all', 'utm', 'disable'].includes(log) ? log : 'all',
      nat: typeof source.nat === 'boolean' ? source.nat : false,
      securityProfiles,
      preferredWanIntf: validWanNames.has(preferredWanIntf) ? preferredWanIntf : null,
      wanOverrides,
    },
  };
}

function applyPolicyUserDecisions(authoritativePolicies, submittedPolicies, fortiConfig, observedFlows) {
  const policies = structuredClone(authoritativePolicies || []);
  const issues = [];
  const serviceDefinitions = new Map();
  const addressNamesByTarget = new Map();
  const addressTargetsByName = new Map();
  const registerServiceDefinition = (name, signature, policyIndex) => {
    const key = name.toLowerCase();
    const previous = serviceDefinitions.get(key);
    if (previous && previous !== signature) {
      issues.push({ level: 'error', code: 'SERVICE_NAME_CONFLICT', msg: `Policy #${policyIndex + 1}: nom de service "${name}" utilisé pour plusieurs définitions` });
      return false;
    }
    serviceDefinitions.set(key, signature);
    return true;
  };
  const registerAddressDefinition = (name, target, policyIndex) => {
    if (!name || !target || name.toLowerCase() === 'all'
        || name.length > 79 || /["\\?*#\u0000-\u001f\u007f]/.test(name)) {
      issues.push({ level: 'error', code: 'ADDRESS_NAME_INVALID', msg: `Policy #${policyIndex + 1}: nom d’adresse invalide "${name}"` });
      return false;
    }
    const normalizedName = name.toLowerCase();
    const previousName = addressNamesByTarget.get(target);
    const previousTarget = addressTargetsByName.get(normalizedName);
    if ((previousName && previousName !== name) || (previousTarget && previousTarget !== target)
        || (fortiConfig?.addresses?.[name] && fortiConfig.addresses[name].cidr !== target)
        || fortiConfig?.addressGroups?.[name]) {
      issues.push({ level: 'error', code: 'ADDRESS_NAME_CONFLICT', msg: `Policy #${policyIndex + 1}: nom d’adresse "${name}" incompatible avec "${target}"` });
      return false;
    }
    addressNamesByTarget.set(target, name);
    addressTargetsByName.set(normalizedName, target);
    return true;
  };
  for (let index = 0; index < policies.length; index++) {
    const policy = policies[index];
    const submitted = submittedPolicies?.[index] || {};
    const acceptedRiskInput = submitted._acceptedRisks;
    const acceptedRisks = new Set();
    if (acceptedRiskInput !== undefined) {
      const valid = Array.isArray(acceptedRiskInput)
        && acceptedRiskInput.every(code => code === 'POLICY_AFFINITY_UNPROVEN');
      if (!valid) {
        issues.push({ level: 'error', code: 'RISK_DECISION_INVALID', msg: `Policy #${index + 1}: acceptation de risque invalide` });
      } else {
        acceptedRiskInput.forEach(code => acceptedRisks.add(code));
      }
    }
    const addRisk = (code, msg, detail, recommendation) => {
      const accepted = acceptedRisks.has(code);
      issues.push({
        level: accepted ? 'warn' : 'risk', code, msg, detail, recommendation,
        overridable: true,
        accepted: accepted || undefined,
      });
    };
    delete policy.serviceNames;
    delete policy.action;
    delete policy.log;
    delete policy.securityProfiles;
    delete policy.nat;
    delete policy._srcAddrGrpFound;
    delete policy._dstAddrGrpFound;
    const representationIssue = policyRepresentationIssue(submitted);
    if (representationIssue) {
      issues.push({ level: 'error', code: 'SCOPE_DECISION_INVALID', msg: `Policy #${index + 1}: ${representationIssue}` });
      continue;
    }
    if (!policy._multiSrcSubnets?.length && !policy._use32Src && policy.analysis?.srcAddr?.found) {
      delete policy._srcAddrName;
      delete policy.srcAddrName;
    }
    if (!policy._multiDstSubnets?.length && !policy._use32Dst && policy.analysis?.dstAddr?.found) {
      delete policy._dstAddrName;
      delete policy.dstAddrName;
    }
    for (const [side, multiField, hostFlag] of [
      ['src', '_multiSrcSubnets', '_use32Src'],
      ['dst', '_multiDstSubnets', '_use32Dst'],
    ]) {
      const address = policy.analysis?.[`${side}Addr`];
      if (policy[multiField]?.length || policy[hostFlag] || address?.found || !address?.cidr) continue;
      const field = `${side}AddrName`;
      const privateField = `_${side}AddrName`;
      const requestedName = String(submitted[privateField] || submitted[field] || address.suggestedName || '').trim();
      if (registerAddressDefinition(requestedName, address.cidr, index)) {
        policy[field] = requestedName;
        delete policy[privateField];
      }
    }
    for (const [side, multiField, hostFlag, groupFlag] of [
      ['src', '_multiSrcSubnets', '_use32Src', '_useSrcGroup'],
      ['dst', '_multiDstSubnets', '_use32Dst', '_useDstGroup'],
    ]) {
      const groupName = submitted[`${side}AddrName`] || submitted[`_${side}AddrName`];
      if (submitted[groupFlag] === true && groupName && fortiConfig?.addressGroups?.[groupName]) {
        issues.push({ level: 'error', code: 'ADDRESS_NAME_CONFLICT', msg: `Policy #${index + 1}: groupe existant non prouvé "${groupName}"` });
      }
      const multi = policy[multiField] || [];
      for (const item of multi) {
        if (item.useSubnet === false) continue;
        const exact = Object.entries(fortiConfig?.addresses || {})
          .find(([, address]) => address.cidr === item.subnet);
        if (exact) {
          item.addrFound = true;
          item.addrName = exact[0];
        } else {
          item.addrFound = false;
          const name = String(item.addrName || suggestAddrName(item.subnet)).trim();
          if (registerAddressDefinition(name, item.subnet, index)) item.addrName = name;
        }
      }
      const hosts = policy[hostFlag]
        ? (policy[side === 'src' ? 'srcHosts' : 'dstHosts'] || [])
        : multi.filter(item => item.useSubnet === false).flatMap(item => item.hosts || []);
      if (hosts.length > 0) {
        const sourceNames = submitted[`_${side}HostNames`] || {};
        const validatedNames = {};
        for (const host of hosts) {
          const exact = Object.entries(fortiConfig?.addresses || {})
            .find(([, address]) => address.cidr === `${host}/32`);
          if (exact) {
            validatedNames[host] = exact[0];
            continue;
          }
          const name = String(sourceNames[host] || `FF_HOST_${host.replace(/\./g, '_')}`).trim();
          if (registerAddressDefinition(name, `${host}/32`, index)) validatedNames[host] = name;
        }
        policy[`_${side}HostNames`] = validatedNames;
      }
    }
    if (policy.dstType === 'public' && policy.dstTarget !== 'all' && policy._dstUseAll === undefined) {
      policy._dstUseAll = false;
    }
    policy._isWan = policy.dstType === 'public';
    const evidenceFlows = (observedFlows || []).filter(flow =>
      isPolicyEvidenceFlow(flow) && flowMatchesPolicyScope(flow, policy)
    );
    const evidenceDstTypes = new Set(evidenceFlows.map(flow => flow.dstType)
      .filter(type => ['private', 'public'].includes(type)));
    if (evidenceDstTypes.size > 0
        && (evidenceDstTypes.size !== 1 || !evidenceDstTypes.has(policy.dstType))) {
      issues.push({ level: 'error', code: 'SCOPE_DECISION_INVALID', msg: `Policy #${index + 1}: type destination absent des flux observés` });
    }
    if (!publicAllProvenanceProven(policy, observedFlows)) {
      addRisk(
        'POLICY_AFFINITY_UNPROVEN',
        `Policy #${index + 1}: provenance destination/service Internet non prouvée`,
        'Cette policy Internet regroupe des destinations et services dont l’association exacte n’est pas démontrée par les logs.',
        'Séparer les policies par destination et services observés, ou accepter explicitement cette permission plus large.',
      );
    }
    if (evidenceFlows.length === 0
        || !policySideElementsProven(policy, evidenceFlows, 'src')
        || !policySideElementsProven(policy, evidenceFlows, 'dst')) {
      issues.push({ level: 'error', code: 'SCOPE_DECISION_INVALID', msg: `Policy #${index + 1}: scope absent des flux observés` });
    }
    const validInterfaces = new Set([
      ...Object.keys(fortiConfig?.interfaces || {}),
      ...Object.keys(fortiConfig?.zones || {}),
      ...(fortiConfig?.sdwanZoneNames || []),
      fortiConfig?.sdwanIntfName,
    ].filter(Boolean));
    const allowedInterfaces = {
      srcintf: new Set(evidenceFlows.map(flow => flow.srcintf).filter(Boolean)),
      dstintf: new Set(evidenceFlows.map(flow => flow.dstintf).filter(Boolean)),
    };
    for (const [field, zoneField, ifaceField] of [
      ['srcintf', 'srcZone', 'srcIface'],
      ['dstintf', 'dstZone', 'dstIface'],
    ]) {
      for (const [zoneName, zone] of Object.entries(fortiConfig?.zones || {})) {
        if ((zone.members || []).some(member => allowedInterfaces[field].has(member))) {
          allowedInterfaces[field].add(zone.name || zoneName);
        }
      }
      if (field === 'dstintf'
          && (fortiConfig?.sdwanMembers || []).some(member => allowedInterfaces[field].has(member))) {
        for (const zoneName of (fortiConfig.sdwanZoneNames || [])) allowedInterfaces[field].add(zoneName);
        if (fortiConfig.sdwanIntfName) allowedInterfaces[field].add(fortiConfig.sdwanIntfName);
      }
      if (allowedInterfaces[field].size === 0) {
        if (policy.analysis?.[zoneField]) allowedInterfaces[field].add(policy.analysis[zoneField]);
        if (policy.analysis?.[ifaceField]) allowedInterfaces[field].add(policy.analysis[ifaceField]);
      }
    }
    for (const [field, label] of [['srcintf', 'source'], ['dstintf', 'destination']]) {
      if (submitted[field] === undefined) continue;
      const values = (Array.isArray(submitted[field]) ? submitted[field] : [submitted[field]])
        .map(value => String(value || '').trim()).filter(Boolean);
      if (values.length === 0 || values.some(value =>
        !validInterfaces.has(value) || !allowedInterfaces[field].has(value)
      )) {
        issues.push({ level: 'error', code: 'INTERFACE_DECISION_INVALID', msg: `Policy #${index + 1}: interface ${label} inconnue "${values.join(', ')}"` });
      } else {
        policy[field] = Array.isArray(submitted[field]) ? values : values[0];
      }
    }
    const interfaceMatches = (choice, actual, side) => {
      if (choice === actual) return true;
      if ((fortiConfig?.zones?.[choice]?.members || []).includes(actual)) return true;
      return side === 'dst'
        && (fortiConfig?.sdwanZoneNames || []).includes(choice)
        && (fortiConfig?.sdwanMembers || []).includes(actual);
    };
    const chosenSrcInterfaces = [].concat(policy.srcintf || policy.analysis?.srcZone || policy.analysis?.srcIface || []).filter(Boolean);
    const chosenDstInterfaces = [].concat(policy.dstintf || policy.analysis?.dstZone || policy.analysis?.dstIface || []).filter(Boolean);
    const pairProven = chosenSrcInterfaces.every(srcChoice =>
      chosenDstInterfaces.every(dstChoice => evidenceFlows.some(flow =>
        interfaceMatches(srcChoice, flow.srcintf, 'src')
        && interfaceMatches(dstChoice, flow.dstintf, 'dst')
      ))
    );
    if (!pairProven) {
      issues.push({ level: 'error', code: 'INTERFACE_DECISION_INVALID', msg: `Policy #${index + 1}: paire d’interfaces absente des flux observés` });
    }
    for (const [field, zoneField, ifaceField, label] of [
      ['srcintf', 'srcZone', 'srcIface', 'source'],
      ['dstintf', 'dstZone', 'dstIface', 'destination'],
    ]) {
      const effective = policy[field] || policy.analysis?.[zoneField] || policy.analysis?.[ifaceField];
      const values = (Array.isArray(effective) ? effective : [effective]).filter(Boolean).map(String);
      if (values.length === 0 || values.some(value =>
        !validInterfaces.has(value) || !allowedInterfaces[field].has(value)
      )) {
        issues.push({ level: 'error', code: 'INTERFACE_DECISION_INVALID', msg: `Policy #${index + 1}: interface ${label} effective inconnue "${values.join(', ')}"` });
      }
    }
    if (submitted.action != null) {
      const action = String(submitted.action).toLowerCase();
      if (!['accept', 'deny'].includes(action)) {
        issues.push({ level: 'error', code: 'ACTION_DECISION_INVALID', msg: `Policy #${index + 1}: action invalide "${submitted.action}"` });
      } else {
        policy.action = action;
      }
    }
    if (submitted.log != null) {
      const log = String(submitted.log).toLowerCase();
      if (!['all', 'utm', 'disable'].includes(log)) {
        issues.push({ level: 'error', code: 'LOG_DECISION_INVALID', msg: `Policy #${index + 1}: mode de log invalide "${submitted.log}"` });
      } else {
        policy.log = log;
      }
    }
    if (submitted.nat != null) {
      if (typeof submitted.nat !== 'boolean') {
        issues.push({ level: 'error', code: 'NAT_DECISION_INVALID', msg: `Policy #${index + 1}: décision NAT invalide` });
      } else {
        policy.nat = submitted.nat;
      }
    }
    if (submitted.securityProfiles != null) {
      const selectedProfiles = {};
      if (typeof submitted.securityProfiles !== 'object' || Array.isArray(submitted.securityProfiles)) {
        issues.push({ level: 'error', code: 'SECURITY_PROFILE_DECISION_INVALID', msg: `Policy #${index + 1}: profils de sécurité mal formés` });
      } else {
        for (const [key, name] of Object.entries(submitted.securityProfiles)) {
          if (!['antivirus', 'webfilter', 'ips', 'sslSsh', 'profileGroup'].includes(key)
              || !(fortiConfig?.securityProfiles?.[key] || []).includes(name)) {
            issues.push({ level: 'error', code: 'SECURITY_PROFILE_DECISION_INVALID', msg: `Policy #${index + 1}: profil ${key} inconnu "${name}"` });
          } else {
            selectedProfiles[key] = name;
          }
        }
      }
      policy.securityProfiles = selectedProfiles;
    }
    if (submitted._serviceReuse !== undefined) {
      const reuseEntries = submitted._serviceReuse && typeof submitted._serviceReuse === 'object'
        && !Array.isArray(submitted._serviceReuse)
        ? Object.entries(submitted._serviceReuse)
        : [];
      if (reuseEntries.length === 0 && Object.keys(submitted._serviceReuse || {}).length > 0) {
        issues.push({ level: 'error', code: 'SERVICE_REUSE_DECISION_INVALID', msg: `Policy #${index + 1}: choix de réutilisation invalide` });
      }
      for (const [rawKey, requestedName] of reuseEntries) {
        const key = String(rawKey).toUpperCase();
        const accepted = (policy.analysis?.services || []).find(service =>
          serviceTransportKeys(service).includes(key)
          && service.found === true
          && service.compatibilityAccepted === true
          && service.name === requestedName
        );
        if (!accepted) {
          issues.push({ level: 'error', code: 'SERVICE_REUSE_DECISION_INVALID', msg: `Policy #${index + 1}: réutilisation stale ou forgée "${rawKey}" → "${requestedName}"` });
        }
      }
    }
    const submittedServices = submitted.analysis?.services || [];
    const mergedServices = Array.isArray(submitted._mergedServices) ? submitted._mergedServices : [];
    for (const service of (policy.analysis?.services || [])) {
      if (!serviceEvidenceProven(service, evidenceFlows)) {
        issues.push({ level: 'error', code: 'SERVICE_DECISION_UNPROVEN', msg: `Policy #${index + 1}: service "${service.label || service.name || '?'}" absent des flux observés` });
        continue;
      }
      if (service.found) {
        if (!foundServiceEvidenceProven(service, evidenceFlows, fortiConfig)) {
          issues.push({ level: 'error', code: 'SERVICE_DECISION_UNPROVEN', msg: `Policy #${index + 1}: service "${service.name}" incompatible avec le tuple observé` });
        }
        continue;
      }
      const requested = submittedServices.find(item => item.label === service.label);
      const suggestedName = typeof requested?.suggestedName === 'string' && requested.suggestedName.trim()
        ? requested.suggestedName.trim()
        : String(service.suggestedName || '').trim();
      const serviceKeys = serviceTransportKeys(service);
      const requestedKeys = serviceTransportKeys(requested);
      const multiSpecific = serviceKeys.length > 1
        && requestedKeys.length === serviceKeys.length
        && serviceKeys.every(key => requestedKeys.includes(key))
        && serviceKeys.every(key => submitted._resolvedServiceKeys?.[key] === 'specific');
      if (multiSpecific) {
        const protos = [...new Set(serviceKeys.map(key => key.split('/')[0]))];
        const proven = serviceKeys.every(key =>
          evidenceFlows.some(flow => flowServiceTechnicalKey(flow) === key
            && String(flow.service || '').toUpperCase() === String(service.label || '').toUpperCase()));
        if (protos.length !== 1 || !['TCP', 'UDP'].includes(protos[0]) || !proven) {
          issues.push({ level: 'error', code: 'SERVICE_DECISION_UNPROVEN', msg: `Policy #${index + 1}: service multiport "${service.label}" non prouvé` });
          continue;
        }
        service.proto = protos[0];
        service.ports = serviceKeys.map(key => Number(key.split('/')[1])).sort((a, b) => a - b);
        service.sourcePorts = [...service.ports];
      } else if (!service.port || !service.proto) {
        const tuples = observedServiceTuples(policy, service.label, observedFlows);
        if (tuples.length !== 1) {
          issues.push({ level: 'error', code: 'SERVICE_DECISION_AMBIGUOUS', msg: `Policy #${index + 1}: service "${service.label}" sans tuple protocole/port unique` });
          continue;
        }
        service.port = tuples[0].port;
        service.proto = tuples[0].proto;
      }
      const nameIssue = serviceNameDecisionIssue(suggestedName, fortiConfig);
      if (nameIssue) {
        issues.push({ level: 'error', code: nameIssue.code, msg: `Policy #${index + 1}: ${nameIssue.msg}` });
        continue;
      }
      const definition = service.ports?.length
        ? `${service.proto}/${service.ports.join(',')}` : `${service.proto}/${service.port}`;
      if (!registerServiceDefinition(suggestedName, definition, index)) continue;
      service.suggestedName = suggestedName;
    }
    if (mergedServices.length > 0) {
      const authoritativeKeys = new Set((policy.analysis?.services || []).map(serviceTransportKey).filter(Boolean));
      const observedKeys = observedPolicyTransportKeys(policy, observedFlows);
      const consumedKeys = new Set();
      const validatedMerged = [];
      const mergedNames = new Set();
      for (const merged of mergedServices) {
        const proto = String(merged?.proto || '').toUpperCase();
        const sourcePorts = [...new Set((merged?.sourcePorts || []).map(Number))].sort((a, b) => a - b);
        const name = typeof merged?.name === 'string' ? merged.name.trim() : '';
        const nameIssue = serviceNameDecisionIssue(name, fortiConfig);
        const sourceKeys = sourcePorts.map(port => `${proto}/${port}`);
        let invalid = !['TCP', 'UDP'].includes(proto)
          || sourcePorts.length < 2
          || (Array.isArray(merged?.ports) && typeof merged?.portRange === 'string')
          || sourcePorts.some(port => !Number.isInteger(port) || port < 1 || port > 65535)
          || sourceKeys.some(key => !authoritativeKeys.has(key) || !observedKeys.has(key) || consumedKeys.has(key));
        let ports = null;
        let portRange = null;
        if (Array.isArray(merged?.ports)) {
          const requestedPorts = [...new Set(merged.ports.map(Number))].sort((a, b) => a - b);
          invalid ||= requestedPorts.length !== sourcePorts.length
            || requestedPorts.some((port, offset) => port !== sourcePorts[offset]);
          ports = sourcePorts;
        } else if (typeof merged?.portRange === 'string') {
          const range = merged.portRange.match(/^(\d+)-(\d+)$/);
          const start = range ? Number(range[1]) : NaN;
          const end = range ? Number(range[2]) : NaN;
          invalid ||= !range || start !== sourcePorts[0] || end !== sourcePorts[sourcePorts.length - 1];
          invalid ||= sourcePorts.some((port, offset) => offset > 0 && port !== sourcePorts[offset - 1] + 1);
          if (range) portRange = `${start}-${end}`;
        } else {
          invalid = true;
        }
        if (nameIssue || mergedNames.has(name.toLowerCase())) invalid = true;
        const definition = portRange ? `${proto}/${portRange}` : `${proto}/${sourcePorts.join(',')}`;
        if (!invalid && !registerServiceDefinition(name, definition, index)) invalid = true;
        if (invalid) {
          issues.push({ level: 'error', code: nameIssue?.code || 'MERGED_SERVICE_DECISION_INVALID', msg: `Policy #${index + 1}: fusion de service invalide "${name}"` });
          continue;
        }
        sourceKeys.forEach(key => consumedKeys.add(key));
        mergedNames.add(name.toLowerCase());
        validatedMerged.push({ label: name, found: false, name: null, source: null, suggestedName: name, isNamed: false, proto, ports, portRange, sourcePorts, _isMerged: true });
      }
      if (validatedMerged.length > 0) {
        policy.analysis.services = (policy.analysis.services || [])
          .filter(service => !consumedKeys.has(serviceTransportKey(service)))
          .concat(validatedMerged);
      }
    }
    if ((policy.analysis?.services || []).length === 0) {
      issues.push({ level: 'error', code: 'SERVICE_DECISION_EMPTY', msg: `Policy #${index + 1}: aucun service validé` });
    } else if (!policyAffinityProven(policy, evidenceFlows)) {
      const summarize = values => {
        const unique = [...new Set(values.filter(Boolean))];
        return `${unique.slice(0, 8).join(', ')}${unique.length > 8 ? `, … (+${unique.length - 8})` : ''}`;
      };
      const sources = policyAffinityScopes(policy, 'src').map(scope => scope.host || scope.subnet);
      const destinations = policyAffinityScopes(policy, 'dst').map(scope => scope.host || scope.subnet);
      const services = (policy.analysis?.services || []).flatMap(serviceTransportKeys);
      addRisk(
        'POLICY_AFFINITY_UNPROVEN',
        `Policy #${index + 1}: combinaison source/destination/service absente des flux observés`,
        `Périmètre concerné — sources: ${summarize(sources)}; destinations: ${summarize(destinations)}; services: ${summarize(services)}. Toutes les combinaisons de ce produit n’ont pas été observées.`,
        'Séparer les policies selon les associations destination/service observées, ou accepter explicitement cette permission plus large.',
      );
    }
  }
  return {
    ok: !issues.some(issue => issue.level === 'error' || issue.level === 'risk'),
    policies,
    issues,
  };
}

// ─── CLI config generator ─────────────────────────────────────────────────────

// Sanitise une valeur pour insertion dans une commande CLI FortiGate (entre quotes)
// M7: neutralise aussi ? * # (wildcards / commentaire interprétés par le CLI FortiGate)
function safeCli(str) { return (str || '').replace(/["\\?*#]/g, '_').replace(/[\r\n]/g, ''); }

// M8: enregistre un groupe d'adresses en évitant les collisions de noms.
// Deux policies au même 1er subnet peuvent produire le même nom de groupe avec des membres
// différents → sans dédup, le 2e .set() écrase le 1er silencieusement (membres erronés).
// Si le nom existe avec des membres identiques → réutilise ; sinon suffixe _2, _3…
// Retourne le nom effectivement utilisé (à référencer dans la policy).
function registerAddrGroup(map, baseName, members) {
  const sig = (arr) => [...arr].sort().join('');
  const wanted = sig(members);
  let name = baseName;
  let n = 1;
  while (map.has(name)) {
    if (sig(map.get(name)) === wanted) return name;  // déjà exactement ce groupe
    name = `${baseName}_${++n}`;
  }
  map.set(name, members);
  return name;
}

// Consolidate sorted port numbers into compact range notation for FortiGate CLI
// e.g. [1046,1047,1131,1132,1133] → "1046-1047 1131-1133"
function consolidatePortRanges(ports) {
  if (!ports || ports.length === 0) return '';
  const sorted = [...ports].sort((a, b) => a - b);
  const ranges = [];
  let start = sorted[0], prev = sorted[0];
  for (let i = 1; i < sorted.length; i++) {
    const cur = sorted[i];
    if (cur === prev + 1) { prev = cur; continue; }
    ranges.push(start === prev ? String(start) : `${start}-${prev}`);
    start = cur; prev = cur;
  }
  ranges.push(start === prev ? String(start) : `${start}-${prev}`);
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
        srcAddrGrpName = registerAddrGroup(newAddrGroups,
          p._srcAddrName || `FF_GRP_SRC_${suggestAddrName(p._multiSrcSubnets[0].subnet)}`, allSrcNames);
      }
    } else if (p._isSvcMerge && p._mergedSrcSubnets && p._mergedSrcSubnets.length > 1) {
      // Fusion par service : créer un groupe d'adresses pour les sources fusionnées
      const subnetNames = p._mergedSrcSubnets.map(s => suggestAddrName(s));
      p._mergedSrcSubnets.forEach((cidr, i) => newAddresses.set(cidr, subnetNames[i]));
      srcAddrNames = subnetNames;
      srcAddrGrpName = registerAddrGroup(newAddrGroups,
        p._srcAddrName || `FF_SVC_GRP_${suggestAddrName(p._mergedSrcSubnets[0])}`, subnetNames);
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
        srcAddrNames = hostNames;
        srcAddrGrpName = registerAddrGroup(newAddrGroups,
          p.srcAddrName || `FF_HOSTS_${suggestAddrName(p.srcSubnet)}`, hostNames);
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
      srcAddrGrpName = registerAddrGroup(newAddrGroups,
        p.srcAddrName || p.policyName || `FF_GRP_${suggestAddrName(subnets[0])}`, srcAddrNames);
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
    // ── WAN policy : dstaddr "all" uniquement sur décision explicite, sinon destination spécifique ──
    if ((p._isWan || p.dstType === 'public') && (p._dstUseAll === true || p.dstTarget === 'all')) {
      dstAddrName = 'all';
    } else if (p._isWan || p.dstType === 'public') {
      // Mode IPs spécifiques pour policy WAN
      if (p._use32Dst && p.dstHosts?.length > 0) {
        const hostNames = p.dstHosts.map(h => {
          const { name, isNew } = resolveHost32(h, p._dstHostNames);
          if (isNew) newAddresses.set(`${h}/32`, name);
          return name;
        });
        dstAddrName = hostNames.length === 1 ? hostNames[0] : hostNames;
      } else if (p.dstHosts?.length > 0) {
        const hostNames = p.dstHosts.map(h => {
          const { name, isNew } = resolveHost32(h, p._dstHostNames);
          if (isNew) newAddresses.set(`${h}/32`, name);
          return name;
        });
        dstAddrName = hostNames.length === 1 ? hostNames[0] : hostNames;
      } else if (p.dstTarget && p.dstTarget !== 'all') {
        const ip = p.dstTarget;
        const cidr = ip.includes('/') ? ip : `${ip}/32`;
        const name = p._dstAddrName || p.dstAddrName || suggestAddrName(cidr);
        newAddresses.set(cidr, name);
        dstAddrName = name;
      } else {
        dstAddrName = 'all';
      }
    // ── Multi-dst : "all" si _dstUseAll=true ──
    } else if (p._isMultiDst && p._dstUseAll === true && (p._isWan || p.dstType === 'public')) {
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
          dstAddrName = registerAddrGroup(newAddrGroups,
            p.dstAddrName || `GRP_${(p.policyIds||['0'])[0]}_DST`, uniqueDstNames);
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
          newServices.set(customName, {
            name: customName, port: resolvedPort, proto: resolvedProto,
          });
        }
      }
    }
    serviceNames.splice(0, serviceNames.length, ...new Set(serviceNames));
    if (serviceNames.length === 0) {
      throw new Error(`Policy "${p.policyName || p.name || p.id || '?'}" sans service validé`);
    }

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
      action:      p.action,
      log:         p.log,
      securityProfiles: p.securityProfiles,
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
    const srcIntf = p.srcintf || p._srcintf || a.srcZone || a.srcIface;
    const dstIntf = p.dstintf || p._dstintf || a.dstZone || a.dstIface;
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
  extractKnownSubnets,
  preserveDestinationServiceAffinity,
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
  applyPolicyUserDecisions,
  validateGenerationOptions,
  validatePolicyDecisionShapes,
  PREDEFINED,
  parseFullRoutingTable,
  parseOspfRoutingTable,
  parseBgpNetworkTable,
  sortRoutes,
  formatExistingPolicies,
};

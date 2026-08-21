'use strict';

const { buildAddressChoices, validateAddressSelection } = require('./address-selection');

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
  for (const name of sectionNames) {
    results[name] = {};
    // Les clés numériques d'un objet JavaScript sont réordonnées. Conserver
    // séparément l'ordre FortiGate est indispensable pour simuler le first-match.
    Object.defineProperty(results[name], '__order', { value: [], enumerable: false });
  }
  const storeEdit = (section, name, props) => {
    if (!Object.prototype.hasOwnProperty.call(results[section], name)) results[section].__order.push(name);
    results[section][name] = props;
  };

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
        if (editName !== null) storeEdit(inTarget, editName, editProps);
        inTarget  = null;
        editName  = null;
        editProps = {};
      }
      continue;
    }

    if (depth !== 1) continue; // ignore nested section content

    if (t.startsWith('edit ')) {
      if (editName !== null) storeEdit(inTarget, editName, editProps);
      editName  = t.slice(5).trim().replace(/^"|"$/g, '');
      editProps = {};
    } else if (t === 'next') {
      if (editName !== null) storeEdit(inTarget, editName, editProps);
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

function hasEditableConfigPath(lines, parentName, childName = null) {
  const stack = [];
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('config ')) {
      stack.push(line.slice(7).trim());
      continue;
    }
    if (line === 'end') {
      stack.pop();
      continue;
    }
    if (!line.startsWith('edit ')) continue;
    const inParent = stack.includes(parentName);
    const inTarget = childName
      ? stack[stack.length - 1] === childName
      : stack[stack.length - 1] === parentName;
    if (inParent && inTarget) return true;
  }
  return false;
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
  const parts = String(ip || '').split('.');
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    throw new Error(`Adresse IPv4 invalide : ${ip}`);
  }
  return parts.reduce((a, o) => (a * 256) + Number(o), 0) >>> 0;
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
    // Normaliser sur l'adresse réseau : "10.1.6.5 255.255.255.0" → "10.1.6.0/24"
    // (sinon objets dupliqués + réutilisation/réconciliation ratées).
    return `${networkAddress(parts[0], bits)}/${bits}`;
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
      // Borne au max port réel (65535), pas une limite arbitraire qui tronquait les
      // services à large plage (ex 1-65535) → matching/couverture incomplets.
      for (let i = a; i <= Math.min(b, 65535); i++) ports.push(i);
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

// ─── Config identity ──────────────────────────────────────────────────────────

function unquoteConfigValue(value) {
  return String(value || '').trim().replace(/^"|"$/g, '');
}

// Read top-level `set` directives from a non-edit FortiOS config section.
// This deliberately ignores nested config blocks so a child setting cannot
// masquerade as the device/global identity of the selected scope.
function extractTopLevelSettings(lines, sectionName) {
  const settings = {};
  let inSection = false;
  let depth = 0;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (!inSection) {
      if (line === `config ${sectionName}`) {
        inSection = true;
        depth = 1;
      }
      continue;
    }
    if (line.startsWith('config ')) {
      depth++;
      continue;
    }
    if (line === 'end') {
      depth--;
      if (depth === 0) break;
      continue;
    }
    if (depth !== 1 || !line.startsWith('set ')) continue;
    const rest = line.slice(4).trim();
    const split = rest.indexOf(' ');
    if (split <= 0) {
      settings[rest] = '';
      continue;
    }
    settings[rest.slice(0, split)] = unquoteConfigValue(rest.slice(split + 1));
  }
  return settings;
}

function parseConfigIdentity(lines, vdomList, selectedVdom, activeVdom) {
  const global = extractTopLevelSettings(lines, 'system global');
  const haSettings = extractTopLevelSettings(lines, 'system ha');
  const firstNonEmpty = (...values) => values
    .map(value => unquoteConfigValue(value))
    .find(value => value !== '') || null;
  const hostname = firstNonEmpty(global.hostname);
  // FortiOS backups do not normally expose the appliance serial. Preserve an
  // explicitly exported value when present, but never infer it from hostname.
  const devid = firstNonEmpty(
    global.devid,
    global['device-id'],
    global['serial-number'],
    global.serial,
  );
  const selectionExplicit = vdomList.length <= 1 || Boolean(selectedVdom);
  return {
    hostname,
    devid,
    serial: devid,
    vdom: activeVdom || null,
    selectedVdom: activeVdom || null,
    vdomList: [...vdomList],
    vdomSelectionExplicit: selectionExplicit,
    vdomSelectionRequired: vdomList.length > 1 && !selectionExplicit,
    ha: {
      enabled: Object.keys(haSettings).length > 0,
      groupName: firstNonEmpty(haSettings['group-name']),
      groupId: firstNonEmpty(haSettings['group-id']),
      memberDeviceIds: [],
    },
  };
}

// ─── Main config parser ───────────────────────────────────────────────────────

function parseFortiConfig(text, selectedVdom = null) {
  const lines = text.split(/\r?\n/);

  // ── Multi-VDOM: if present, extract the target VDOM block and parse it ──
  const vdomList = extractVdomNames(lines);
  if (selectedVdom && !vdomList.includes(selectedVdom)) {
    throw new Error(`VDOM ${selectedVdom} introuvable dans la configuration`);
  }
  let parseLines = lines;
  let parseText  = text;
  let activeVdom = null;
  if (vdomList.length > 0) {
    activeVdom = (selectedVdom && vdomList.includes(selectedVdom)) ? selectedVdom : vdomList[0];
    parseLines = extractVdomLines(lines, activeVdom);
    parseText  = parseLines.join('\n');
  }

  const identity = parseConfigIdentity(lines, vdomList, selectedVdom, activeVdom);
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
  // En multi-VDOM, les interfaces résident généralement dans la configuration
  // globale avec "set vdom". Les rattacher explicitement au VDOM actif.
  if (vdomList.length > 0) {
    const globalInterfaces = extractSection(lines, 'system interface');
    const scopedInterfaces = {};
    Object.defineProperty(scopedInterfaces, '__order', { value: [], enumerable: false });
    for (const name of (globalInterfaces.__order || Object.keys(globalInterfaces))) {
      const props = globalInterfaces[name];
      const ifaceVdom = String(props.vdom || '').replace(/^"|"$/g, '');
      if (ifaceVdom === activeVdom) {
        scopedInterfaces[name] = props;
        scopedInterfaces.__order.push(name);
      }
    }
    // Ne remplacer que si la section globale a effectivement fourni le scope attendu.
    if (scopedInterfaces.__order.length > 0) _sections['system interface'] = scopedInterfaces;
  }

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
  for (const [name, props] of Object.entries(rawCustomSvcs)) {
    const proto = (props.protocol || 'TCP/UDP/SCTP').toUpperCase();
    const icmptype = props.icmptype !== undefined && props.icmptype !== '' ? parseInt(props.icmptype, 10) : null;
    const icmpcode = props.icmpcode !== undefined && props.icmpcode !== '' ? parseInt(props.icmpcode, 10) : null;
    const tcpPorts = parsePorts(props['tcp-portrange'] || '');
    const udpPorts = parsePorts(props['udp-portrange'] || '');
    customServices[name] = {
      name,
      proto,
      tcpPorts,
      udpPorts,
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
  for (const editId of (rawPolicies.__order || Object.keys(rawPolicies))) {
    const props = rawPolicies[editId];
    const unsupportedCoverageFeatures = [];
    if (props.schedule && props.schedule.replace(/^"|"$/g, '').toLowerCase() !== 'always') {
      unsupportedCoverageFeatures.push('schedule');
    }
    for (const feature of [
      'srcaddr-negate', 'dstaddr-negate', 'service-negate',
      'internet-service', 'internet-service-src', 'identity-based',
    ]) {
      if (String(props[feature] || '').toLowerCase() === 'enable') unsupportedCoverageFeatures.push(feature);
    }
    if (props.groups || props.users) unsupportedCoverageFeatures.push('identity');
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
      unsupportedCoverageFeatures,
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
    const role = String(props.role || '').replace(/^"|"$/g, '').toLowerCase();
    const roleLan  = role === 'lan' || role === 'dmz';
    const roleWan  = role === 'wan';
    const modeDhcp = props.mode === 'dhcp' || props.mode === 'pppoe';
    const isWan = !isTunnel && (roleWan || (!roleLan && (modeDhcp || (!isPrivateIP(props.ip?.split(' ')[0] || '') && !!props.ip))));
    interfaces[name] = {
      name,
      rawIp:    props.ip || '',
      cidr,
      prefix,
      alias:    props.alias || name,
      type:     props.type  || 'physical',
      role:     role || null,
      isWan,
      _roleWan: roleWan,
      isTunnel,
      isSdwan:  sdwanMembers.includes(name),
      vrf:       parseInt(props.vrf || '0', 10) || 0,
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

  // Une VRF non par défaut exige un contexte de routage que la matrice
  // standard ne peut pas déduire de manière certaine.
  const hasNonDefaultVrf = Object.values(interfaces).some(iface => iface.vrf !== 0);
  // Les règles PBR et les règles de service SD-WAN influencent le chemin réel
  // en fonction du tuple. Elles sont signalées au preflight : la simple table
  // de routage ne suffit alors pas à certifier l'interface de sortie.
  const hasPolicyRoutes = hasEditableConfigPath(parseLines, 'router policy');
  const hasSdwanRules = hasEditableConfigPath(parseLines, 'system sdwan', 'service')
    || hasEditableConfigPath(parseLines, 'system virtual-wan-link', 'service');

  // ── Security profiles ──
  const securityProfiles = {
    antivirus:    Object.keys(_sections['antivirus profile'] || {}),
    webfilter:    Object.keys(_sections['webfilter profile'] || {}),
    ips:          Object.keys(_sections['ips sensor'] || {}),
    sslSsh:       Object.keys(_sections['firewall ssl-ssh-profile'] || {}),
    profileGroup: Object.keys(_sections['firewall profile-group'] || {}),
  };

  return { addresses, addressGroups, customServices, serviceGroups, interfaces, zones, sdwanMembers, sdwanZoneNames, sdwanEnabled, sdwanIntfName, vdomList, selectedVdom: activeVdom, hasVdom: vdomList.length > 0, identity, hostname: identity.hostname, devid: identity.devid, serial: identity.serial, vdomSelectionRequired: identity.vdomSelectionRequired, staticRoutes, fullRoutes, hasBgp, hasOspf, hasNonDefaultVrf, hasPolicyRoutes, hasSdwanRules, existingPolicies, securityProfiles };
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
    if (String(props.status || 'enable').replace(/^"|"$/g, '') === 'disable') continue;
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
      gateway:  (props.gateway || '').trim().replace(/^"|"$/g, ''),
      device,
      distance: parseInt(props.distance || '10', 10),
      priority: parseInt(props.priority || '0',  10),
      source:   'static',
    });
  }

  sortRoutes(routes);
  return routes;
}

function sortRoutes(routes) {
  routes.sort((a, b) => {
    const aLen = parseInt(a.dst.split('/')[1] || '0', 10);
    const bLen = parseInt(b.dst.split('/')[1] || '0', 10);
    if (bLen !== aLen) return bLen - aLen;
    const distanceDiff = (a.distance ?? Number.MAX_SAFE_INTEGER) - (b.distance ?? Number.MAX_SAFE_INTEGER);
    if (distanceDiff !== 0) return distanceDiff;
    return (a.priority ?? 0) - (b.priority ?? 0);
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

  sortRoutes(routes);
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
function resolveInterfaceByRoute(dstCidr, routes, skipDefault) {
  const unresolved = { device: null, ambiguous: false, candidates: [] };
  if (!routes || routes.length === 0) return unresolved;
  const targetIp = (dstCidr || '').split('/')[0];
  let targetInt;
  try { targetInt = ip2int(targetIp); } catch { return unresolved; }

  // Collecter toutes les routes correspondantes, puis appliquer la sélection
  // FortiGate. Si plusieurs interfaces restent ex æquo (ECMP), ne pas en choisir
  // une arbitrairement : le moteur supérieur devra demander une décision.
  const matches = [];
  for (const route of routes) {
    const [routeIp, pfxStr] = String(route.dst || '').split('/');
    const pfx = parseInt(pfxStr || '0', 10);
    if (skipDefault && pfx === 0) continue;
    const mask = pfx === 0 ? 0 : (0xFFFFFFFF << (32 - pfx)) >>> 0;
    try {
      if (pfx === 0 || (ip2int(routeIp) & mask) === (targetInt & mask)) matches.push(route);
    } catch { /* route invalide ignorée */ }
  }
  if (!matches.length) return unresolved;
  sortRoutes(matches);
  const best = matches[0];
  const bestPrefix = parseInt(best.dst.split('/')[1] || '0', 10);
  const equivalent = matches.filter(route =>
    parseInt(route.dst.split('/')[1] || '0', 10) === bestPrefix &&
    (route.distance ?? Number.MAX_SAFE_INTEGER) === (best.distance ?? Number.MAX_SAFE_INTEGER) &&
    (route.priority ?? 0) === (best.priority ?? 0)
  );
  const devices = [...new Set(equivalent.map(route => route.device).filter(Boolean))];
  return {
    device: devices.length === 1 ? devices[0] : null,
    ambiguous: devices.length > 1,
    candidates: devices,
  };
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
  const broaderMatches = [];
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
            if (addr.startInt === targetInt && addr.endInt === targetInt) {
              matches.push({ name, cidr: `${ip}/32`, source: 'config-range-exact' });
            } else {
              broaderMatches.push({ name, cidr: addr.cidr, source: 'config-range-broader' });
            }
          }
        } catch {}
      }
    }
  }
  // Exact matches take priority over range matches
  if (matches.length === 0) return { found: false, broaderMatches };
  return { found: true, name: matches[0].name, source: matches[0].source, allMatches: matches, broaderMatches };
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
    if (svc.icmpcode === null || svc.icmpcode !== code) continue;
    return { name, source: 'custom', portHint: `ICMP type ${type} code ${code}` };
  }
  // Ne jamais rabattre un type/code précis vers ALL_ICMP : cela élargirait
  // silencieusement le périmètre du service.
  return null;
}

// Fuzzy name match: find a service by label similarity (prefix/contains) + observed ports filter
function findServiceByName(label, observedPorts, protoName, customServices) {
  // Never fuzzy-match port-notation labels — they have their own resolution path
  if (/^(TCP|UDP)\/\d+$/i.test(label)) return null;
  const norm = label.toLowerCase().replace(/[-_\s]/g, '');

  const isUdp = /^(udp|17)$/i.test(String(protoName));
  const compatibleWithObserved = (cs) => {
    if (!observedPorts?.length) return true;
    const portSet = isUdp ? cs._udpSet : cs._tcpSet;
    const ports = isUdp ? (cs.udpPorts || []) : (cs.tcpPorts || []);
    return observedPorts.every(port => portSet instanceof Set ? portSet.has(Number(port)) : ports.includes(Number(port)));
  };

  // 1. Correspondance exacte, mais jamais au prix d'une incompatibilité port/protocole.
  for (const [name, cs] of Object.entries(customServices)) {
    if (name.toLowerCase() === label.toLowerCase() && compatibleWithObserved(cs)) {
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
    // Si des ports sont observés, aucun candidat incompatible ne doit être retenu.
    if (observedPorts?.length && byPort.length === 0) return null;
    const pool = observedPorts?.length ? byPort : predefCandidates;
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
    if ((cn.startsWith(norm) || norm.startsWith(cn)) && norm.length >= 5 && cn.length >= 5 && compatibleWithObserved(cs)) {
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
    const ports   = isUdp ? svc.udpPorts : svc.tcpPorts;
    const portSet = isUdp ? svc._udpSet  : svc._tcpSet;   // P1: lookup O(1)
    if (ports.length <= maxPortCount && (portSet instanceof Set ? portSet.has(p) : ports.includes(p))) {
      matches.push({ name, source: 'custom', portCount: ports.length });
    }
  }

  if (matches.length === 0) return { found: false };
  // Prefer the most specific match, then an exact object from the loaded
  // configuration over a predefined alias with the same cardinality.
  matches.sort((a, b) => a.portCount - b.portCount
    || (a.source === 'custom' ? 0 : 1) - (b.source === 'custom' ? 0 : 1)
    || a.name.localeCompare(b.name));
  return { found: true, name: matches[0].name, source: matches[0].source, allMatches: matches };
}

function transportProtoName(proto) {
  if (/^(6|tcp)$/i.test(String(proto || ''))) return 'TCP';
  if (/^(17|udp)$/i.test(String(proto || ''))) return 'UDP';
  return '';
}

function transportTupleSet(tuples) {
  const result = new Set();
  for (const tuple of (tuples || [])) {
    const proto = transportProtoName(tuple?.proto);
    const port = Number(tuple?.port ?? tuple?.dstport);
    if (!proto || !Number.isInteger(port) || port < 1 || port > 65535) continue;
    result.add(`${proto}/${port}`);
  }
  return result;
}

function configuredServiceTupleSet(name, source, customServices) {
  const result = new Set();
  if (!name) return result;
  if (source === 'predefined') {
    for (const [port, entry] of Object.entries(PREDEFINED)) {
      if (entry.name !== name) continue;
      if (entry.proto === 'tcp' || entry.proto === 'both') result.add(`TCP/${Number(port)}`);
      if (entry.proto === 'udp' || entry.proto === 'both') result.add(`UDP/${Number(port)}`);
    }
    return result;
  }
  const svc = customServices[name];
  if (!svc) return result;
  for (const port of (svc.tcpPorts || [])) result.add(`TCP/${Number(port)}`);
  for (const port of (svc.udpPorts || [])) result.add(`UDP/${Number(port)}`);
  return result;
}

function setsEqual(a, b) {
  return a.size === b.size && [...a].every(value => b.has(value));
}

function exactServiceDefinition(label, tuples) {
  const observed = transportTupleSet(tuples);
  if (!tuples?.length || observed.size !== tuples.length) return null;
  const tcpPorts = [];
  const udpPorts = [];
  for (const item of observed) {
    const [proto, portText] = item.split('/');
    const port = Number(portText);
    (proto === 'UDP' ? udpPorts : tcpPorts).push(port);
  }
  tcpPorts.sort((a, b) => a - b);
  udpPorts.sort((a, b) => a - b);

  const signature = [...observed].sort().join('|');
  let hash = 2166136261;
  for (let i = 0; i < signature.length; i++) {
    hash ^= signature.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  const safeLabel = String(label || 'SERVICE').toUpperCase().replace(/[^A-Z0-9_-]+/g, '_').slice(0, 40) || 'SERVICE';
  return {
    tcpPorts,
    udpPorts,
    suggestedName: `FF_SVC_${safeLabel}_${(hash >>> 0).toString(16).toUpperCase().padStart(8, '0')}`,
  };
}

// ─── Policy analysis ──────────────────────────────────────────────────────────

// #5: préfixe de nommage configurable (défaut 'FF' → sortie identique à l'historique).
function suggestAddrName(cidr, prefix = 'FF') {
  return prefix + '_' + (cidr || '').replace(/\//g, '_').replace(/\./g, '_');
}

function policyObservedIps(policy, side) {
  const hosts = side === 'src' ? policy?.srcHosts : policy?.dstHosts;
  if (Array.isArray(hosts) && hosts.length > 0) return [...new Set(hosts.filter(Boolean))];
  const target = side === 'src' ? policy?.srcSubnet : policy?.dstTarget;
  if (!target) return [];
  const value = String(target).trim();
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?:\/32)?$/.test(value)) return [value.replace(/\/32$/, '')];
  return [];
}

function buildPolicyAddressChoices(policy, fortiConfig) {
  const sourceIps = policyObservedIps(policy, 'src');
  const destinationIps = policyObservedIps(policy, 'dst');
  return {
    source: sourceIps.length ? buildAddressChoices(sourceIps, fortiConfig) : null,
    destination: destinationIps.length ? buildAddressChoices(destinationIps, fortiConfig) : null,
  };
}

function validatePolicyAddressSelections(selectedPolicies, fortiConfig) {
  const issues = [];
  for (let index = 0; index < (selectedPolicies || []).length; index++) {
    const policy = selectedPolicies[index] || {};
    const selections = policy.addressSelections || policy._addressSelections || {};
    for (const [side, selection] of [['source', selections.source || selections.src], ['destination', selections.destination || selections.dst]]) {
      const prefix = side === 'source' ? 'src' : 'dst';
      if (!selection) {
        if (policy[`_${prefix}CidrOverride`] && policy._serverPolicyBinding !== true) {
          issues.push({
            level: 'error',
            code: 'ADDRESS_SELECTION_INVALID',
            msg: `Policy #${index + 1}: l’override CIDR ${side} exige un choix d’adresse confirmé`,
          });
        }
        continue;
      }
      const observed = policyObservedIps(policy, side === 'source' ? 'src' : 'dst');
      const result = validateAddressSelection(observed, selection, fortiConfig || {});
      if (!result.ok) {
        issues.push({
          level: 'error',
          code: 'ADDRESS_SELECTION_INVALID',
          msg: `Policy #${index + 1}: choix d’adresse ${side} invalide — ${result.errors.join('; ')}`,
        });
      }
    }
  }
  return { ok: issues.length === 0, issues };
}

function selectionModeForPolicy(selection) {
  return String(selection?.mode || selection?.type || '').trim().toLowerCase().replace(/[_ ]/g, '-');
}

function applyPolicyAddressSelections(analyzedPolicies, selectedPolicies) {
  return (analyzedPolicies || []).map((policy, index) => {
    const requested = selectedPolicies?.[index]?.addressSelections || selectedPolicies?.[index]?._addressSelections;
    if (!requested) return policy;
    const next = {
      ...policy,
      addressSelections: requested,
      _policyEngineV2: policy._policyEngineV2 ? { ...policy._policyEngineV2 } : policy._policyEngineV2,
      _segmentationPlan: {
        source: policy._segmentationPlan?.source || (policy._use32Src ? 'host' : 'network'),
        destination: policy._segmentationPlan?.destination || (policy._use32Dst ? 'host' : 'network'),
        services: policy._segmentationPlan?.services || 'separate',
      },
      analysis: {
        ...(policy.analysis || {}),
        srcAddr: { ...(policy.analysis?.srcAddr || {}) },
        dstAddr: { ...(policy.analysis?.dstAddr || {}) },
      },
    };
    for (const [side, selection] of [['source', requested.source || requested.src], ['destination', requested.destination || requested.dst]]) {
      if (!selection) continue;
      const prefix = side === 'source' ? 'src' : 'dst';
      const mode = selectionModeForPolicy(selection);
      const choice = policy.analysis?.addressChoices?.[side];
      if (mode === 'existing' || mode === 'object' || mode === 'existing-object' || mode === 'fortigate-object') {
        const objectName = String(selection.objectName || selection.name || '').trim();
        const object = choice?.existingObjects?.find(candidate => candidate.name === objectName);
        if (!object) continue; // server validation is authoritative; never guess a name here.
        next[`_${prefix}AddrName`] = object.name;
        delete next[`_${prefix}CidrOverride`];
        next[`_use32${prefix === 'src' ? 'Src' : 'Dst'}`] = false;
        next[`_${prefix}Mode`] = 'subnet';
        next._segmentationPlan[side] = 'network';
        if (next._policyEngineV2) next._policyEngineV2.safeExact = false;
        next.analysis[`${prefix}Addr`] = {
          ...next.analysis[`${prefix}Addr`], found: true, name: object.name, cidr: object.cidr, source: 'config',
        };
      } else if (mode === 'subnet' || mode === 'create-subnet') {
        next[`_${prefix}CidrOverride`] = selection.cidr;
        next[`_use32${prefix === 'src' ? 'Src' : 'Dst'}`] = false;
        next[`_${prefix}Mode`] = 'subnet';
        next._segmentationPlan[side] = 'network';
        if (next._policyEngineV2) next._policyEngineV2.safeExact = false;
        next.analysis[`${prefix}Addr`] = {
          ...next.analysis[`${prefix}Addr`], found: false, cidr: selection.cidr,
        };
      } else if (mode === 'hosts' || mode === 'host' || mode === 'create-hosts' || mode === 'host-32') {
        delete next[`_${prefix}CidrOverride`];
        next[`_use32${prefix === 'src' ? 'Src' : 'Dst'}`] = true;
        next[`_${prefix}Mode`] = 'hosts';
        next._segmentationPlan[side] = 'host';
      }
    }
    return next;
  });
}

function addressMatchFromChoices(match, choices) {
  if (!choices?.existingObjects?.length) return match;
  const preferred = choices.existingObjects[0];
  return {
    ...match,
    found: true,
    name: preferred.name,
    cidr: preferred.cidr,
    source: 'config',
    allMatches: choices.existingObjects,
  };
}

function analyzePolicies(policies, fortiConfig, preferredWanIntf) {
  const { addresses, customServices, interfaces, zones } = fortiConfig;

  return policies.map(p => {
    // Source address
    const addressChoices = buildPolicyAddressChoices(p, fortiConfig);
    const srcAddrMatch = addressMatchFromChoices(
      findAddress(p.srcSubnet, addresses),
      p._policyEngineV2 ? null : addressChoices.source,
    );
    // Destination address
    let dstAddrMatch;
    if (p.dstType === 'public') {
      const publicCidr = p.dstTarget
        ? (String(p.dstTarget).includes('/') ? String(p.dstTarget) : `${p.dstTarget}/32`)
        : null;
      dstAddrMatch = publicCidr ? findAddress(publicCidr, addresses) : { found: false, cidr: null };
    } else {
      dstAddrMatch = findAddress(p.dstTarget, addresses);
    }
    dstAddrMatch = addressMatchFromChoices(
      dstAddrMatch,
      p._policyEngineV2 ? null : addressChoices.destination,
    );

    // Services
    const protoLabel = p.protos?.[0] || 'TCP';
    const serviceItems = [];
    const observedTuples = Array.isArray(p.serviceTuples) ? p.serviceTuples : [];
    const tupleProtoLabel = (proto) => /^(17|udp)$/i.test(String(proto)) ? 'UDP'
      : /^(6|tcp)$/i.test(String(proto)) ? 'TCP'
      : String(proto || '').toUpperCase();

    if (p.services && p.services.length > 0) {
      for (const svc of p.services) {
        const svcTuples = observedTuples.filter(t => String(t.service || '').toUpperCase() === String(svc).toUpperCase());
        const relevantTuples = svcTuples.length ? svcTuples : (p.ports || []).map(port => ({ port, proto: protoLabel }));
        const observedPorts = [...new Set(relevantTuples.map(t => Number(t.port)).filter(Number.isInteger))];
        const observedProtoLabels = [...new Set(relevantTuples.map(t => tupleProtoLabel(t.proto)).filter(Boolean))];
        const observedProtoLabel = observedProtoLabels.length === 1 ? observedProtoLabels[0] : null;

        const predefEntries = Object.entries(PREDEFINED).filter(([, entry]) => entry.name === svc);
        const knownPredef = predefEntries.length > 0 && (!relevantTuples.length || relevantTuples.every(t => {
          const port = Number(t.port);
          const proto = tupleProtoLabel(t.proto).toLowerCase();
          return predefEntries.some(([candidatePort, entry]) =>
            Number(candidatePort) === port && (entry.proto === 'both' || entry.proto === proto)
          );
        }));

        const customCandidate = customServices[svc];
        // Pour ICMP sans type/code brut, le nom de service FortiGate observé
        // peut être réutilisé uniquement si la configuration sélectionnée
        // contient exactement le même objet ICMP dans le même scope/VDOM.
        const icmpCustomMatch = customCandidate
          && customCandidate.proto === 'ICMP'
          && relevantTuples.length > 0
          && relevantTuples.every(t => {
            if (!/^(1|icmp)$/i.test(String(t.proto))) return false;
            if (Number.isInteger(t.icmpType) && customCandidate.icmptype !== t.icmpType) return false;
            if (Number.isInteger(t.icmpCode) && customCandidate.icmpcode !== t.icmpCode) return false;
            return true;
          });
        const customMatch = icmpCustomMatch ? customCandidate : customCandidate && (!relevantTuples.length || relevantTuples.every(t => {
          const port = Number(t.port);
          const isUdpTuple = /^(17|udp)$/i.test(String(t.proto));
          const set = isUdpTuple ? customCandidate._udpSet : customCandidate._tcpSet;
          const ports = isUdpTuple ? customCandidate.udpPorts : customCandidate.tcpPorts;
          return set instanceof Set ? set.has(port) : (ports || []).includes(port);
        })) ? customCandidate : null;
        // Try ICMP/CODE/TYPE label matching if not directly found
        const icmpMatch = (!knownPredef && !customMatch) ? findIcmpService(svc, customServices) : null;

        // Fuzzy name match (e.g. "NETBIOS" → "NetBIOS_NS" / "NetBIOS_DS")
        // Skip port-notation labels (e.g. "TCP/853") — they use the port-based fallback path
        const isPortNotationLabel = /^(TCP|UDP)\/\d+$/i.test(svc);
        const fuzzyMatch = (!knownPredef && !customMatch && !icmpMatch && !isPortNotationLabel
          && ['TCP', 'UDP'].includes(observedProtoLabel))
          ? (observedProtoLabel ? findServiceByName(svc, observedPorts, observedProtoLabel, customServices) : null)
          : null;

        // Fallback: if name-based lookup failed, try matching by port against custom services
        let portFallback = null;
        if (!knownPredef && !customMatch && !icmpMatch && !fuzzyMatch) {
          // Port-notation label (e.g. "UDP/11436"): use the port embedded in the label
          const pnm = svc.match(/^(TCP|UDP)\/(\d+)$/i);
          if (pnm) {
            const m = findService(parseInt(pnm[2], 10), pnm[1], customServices, { maxPortCount: 100 });
            if (m.found) portFallback = m;
          } else if (relevantTuples.length > 0) {
            // Chaque couple protocole/port doit résoudre vers le même objet FortiGate.
            const candidates = [];
            for (const tuple of relevantTuples) {
              if (!tuple.port) continue;
              const m = findService(tuple.port, tupleProtoLabel(tuple.proto), customServices, { maxPortCount: 5 });
              if (m.found) candidates.push(m);
            }
            const uniqNames = [...new Set(candidates.map(m => m.name))];
            if (candidates.length === relevantTuples.filter(t => t.port).length && uniqNames.length === 1) {
              portFallback = candidates[0];
            }
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
            portHint = `${observedProtoLabel || protoLabel}: ${observedPorts[0]} (observé)`;
          }
        } else if (fuzzyMatch) {
          portHint = fuzzyMatch.portHint || '';
        } else if (knownPredef) {
          const entries = Object.entries(PREDEFINED).filter(([, e]) => e.name === svc);
          portHint = entries.map(([port, e]) => `${e.proto === 'both' ? 'TCP+UDP' : e.proto.toUpperCase()}: ${port}`).join(', ');
        } else if (observedPorts.length === 1 && observedProtoLabels.length === 1) {
          // Only show an observed tuple when it is unambiguous.
          portHint = `${observedProtoLabel}: ${observedPorts[0]} (observé)`;
        }

        const resolvedName = icmpMatch ? icmpMatch.name
          : fuzzyMatch ? fuzzyMatch.name
          : portFallback ? portFallback.name
          : (knownPredef || customMatch ? svc : null);
        const resolvedSource = icmpMatch ? icmpMatch.source
          : fuzzyMatch ? fuzzyMatch.source
          : portFallback ? portFallback.source
          : (knownPredef ? 'predefined' : customMatch ? 'custom' : null);
        const candidateFound = knownPredef || !!customMatch || !!icmpMatch || !!fuzzyMatch || !!portFallback;
        const observedTransport = transportTupleSet(relevantTuples);
        const configuredTransport = configuredServiceTupleSet(resolvedName, resolvedSource, customServices);
        // Réutiliser un objet uniquement si son périmètre protocole/port est
        // exactement égal aux tuples observés. Un simple sous-ensemble ouvrirait
        // silencieusement des ports supplémentaires.
        const exactExisting = !!icmpMatch || !!icmpCustomMatch || (
          candidateFound
          && relevantTuples.length > 0
          && observedTransport.size === relevantTuples.length
          && setsEqual(observedTransport, configuredTransport)
        );
        const exactDefinition = exactExisting ? null : exactServiceDefinition(svc, relevantTuples);
        serviceItems.push({
          label: svc,
          found: exactExisting,
          name:  exactExisting ? resolvedName : null,
          source: exactExisting ? resolvedSource : (exactDefinition ? 'generated-exact' : null),
          suggestedName: exactExisting ? resolvedName : (exactDefinition?.suggestedName || svc),
          isNamed: true,
          portHint,
          exact: exactExisting || !!exactDefinition,
          constructible: exactExisting || !!exactDefinition,
          tcpPorts: exactDefinition?.tcpPorts || undefined,
          udpPorts: exactDefinition?.udpPorts || undefined,
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

    // Fallback sur chaque tuple protocole/port, sans appliquer le premier protocole à tous les ports.
    if (serviceItems.length === 0) {
      const rawPairs = observedTuples.length
        ? observedTuples.filter(t => t.port).map(t => ({ port: Number(t.port), proto: tupleProtoLabel(t.proto) }))
        : (p.ports || []).map(port => ({ port: Number(port), proto: protoLabel }));
      const uniquePairs = [...new Map(rawPairs.map(pair => [`${pair.proto}|${pair.port}`, pair])).values()];
      for (const { port, proto } of uniquePairs) {
        const match = findService(port, proto, customServices);
        const label = `${port}/${proto}`;
        const exactDefinition = exactServiceDefinition(label, [{ port, proto }]);
        const candidateSet = configuredServiceTupleSet(match.name, match.source, customServices);
        const observedSet = transportTupleSet([{ port, proto }]);
        const exactExisting = match.found && setsEqual(candidateSet, observedSet);
        serviceItems.push({
          label,
          port,
          proto,
          portHint: `${proto}: ${port}`,
          found: exactExisting,
          name:  exactExisting ? match.name : null,
          source: exactExisting ? match.source : 'generated-exact',
          suggestedName: exactExisting ? match.name : (exactDefinition?.suggestedName || `FF_SVC_${port}_${proto}`),
          exact: true,
          constructible: !!exactDefinition || exactExisting,
          tcpPorts: exactExisting ? undefined : exactDefinition?.tcpPorts,
          udpPorts: exactExisting ? undefined : exactDefinition?.udpPorts,
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
      const srcRoute = resolveInterfaceByRoute(p.srcSubnet, routes, true);
      if (srcRoute.device) {
        srcIfaceName   = srcRoute.device;
        srcIfaceSource = 'route';
      } else if (srcRoute.ambiguous) {
        srcIfaceSource = 'ecmp-ambiguous';
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
        const route = resolveInterfaceByRoute(p.dstTarget || '0.0.0.0', routes);
        if (route.device) {
          // Si SD-WAN actif et que la route pointe vers un membre SD-WAN → utiliser l'interface virtuelle
          if (fortiConfig.sdwanEnabled && fortiConfig.sdwanMembers.includes(route.device)) {
            dstIfaceName   = fortiConfig.sdwanIntfName || route.device;
            dstIfaceSource = 'sdwan';
          } else {
            dstIfaceName   = route.device;
            dstIfaceSource = 'route';
          }
        } else if (route.ambiguous) {
          // Un ECMP vers plusieurs interfaces ne permet pas de certifier le chemin
          // d'une policy à partir de la table de routage seule.
          dstIfaceSource = 'ecmp-ambiguous';
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
      const route = resolveInterfaceByRoute(p.dstTarget, routes);
      if (route.device) {
        dstIfaceName   = route.device;
        dstIfaceSource = 'route';
      } else if (route.ambiguous) {
        dstIfaceSource = 'ecmp-ambiguous';
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
        addressChoices,
        srcAddr:    { ...srcAddrMatch,  cidr: srcAddrMatch.cidr || p.srcSubnet, suggestedName: suggestAddrName(p.srcSubnet) },
        dstAddr:    { ...dstAddrMatch,  cidr: dstAddrMatch.cidr || p.dstTarget, suggestedName: suggestAddrName(p.dstTarget) },
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
    namingPrefix   = 'FF',
    target         = 'fortigate',   // #9: 'fortigate' (CLI device) | 'fmg-script' (script Policy Package)
  } = opts;

  // #5: préfixe de nommage (assaini) — défaut 'FF'. Utilisé pour TOUS les objets générés.
  const NP = safeCli(String(namingPrefix || 'FF')).replace(/_+$/, '') || 'FF';

  // Helper: resolve a /32 host — use existing object if found, otherwise suggest a new name
  function resolveHost32(ip, customNames) {
    const cidr = `${ip}/32`;
    const existing = findAddress(cidr, addresses);
    if (existing.found) return { name: existing.name, isNew: false };
    // Nettoyer le nom si corruption "IP=Nom" stockée par l'ancien import positionnel
    const raw = customNames?.[ip];
    const pfx = ip + '=';
    const cleanedName = raw && raw.startsWith(pfx) ? raw.slice(pfx.length) : raw;
    const name = cleanedName || `${NP}_HOST_${ip.replace(/\./g, '_')}`;
    return { name, isNew: true };
  }

  const newAddresses  = new Map();  // cidr → name
  const newAddressNames = new Map(); // name → cidr (détection de collision)
  const newAddrGroups = new Map();  // grpName → [memberNames]
  const newServices   = new Map();  // "port/proto" → {name, port, proto}
  const policyBlocks  = [];

  const registerGeneratedAddress = (cidr, name) => {
    const match = String(cidr || '').match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!match) throw new Error(`CIDR généré invalide : "${cidr || ''}"`);
    const prefix = Number(match[2]);
    if (prefix < 0 || prefix > 32) throw new Error(`Préfixe CIDR invalide : "${cidr}"`);
    const normalized = `${networkAddress(match[1], prefix)}/${prefix}`;
    const objectName = String(name || '').trim();
    if (!objectName) throw new Error(`Objet adresse sans nom pour ${normalized}`);

    const existingName = newAddresses.get(normalized);
    if (existingName && existingName !== objectName) {
      throw new Error(`Collision d'adresses : ${normalized} demandé sous "${existingName}" et "${objectName}"`);
    }
    const existingCidr = newAddressNames.get(objectName);
    if (existingCidr && existingCidr !== normalized) {
      throw new Error(`Collision de nom d'adresse : "${objectName}" désigne ${existingCidr} et ${normalized}`);
    }
    newAddresses.set(normalized, objectName);
    newAddressNames.set(objectName, normalized);
  };

  const registerGeneratedService = (name, definition) => {
    const objectName = String(name || '').trim();
    if (!objectName) throw new Error('Objet service sans nom');
    const normalized = {
      ...definition,
      name: objectName,
      tcpPorts: [...new Set((definition.tcpPorts || []).map(Number))].sort((a, b) => a - b),
      udpPorts: [...new Set((definition.udpPorts || []).map(Number))].sort((a, b) => a - b),
    };
    const signature = JSON.stringify(normalized);
    const existing = newServices.get(objectName);
    if (existing && JSON.stringify(existing) !== signature) {
      throw new Error(`Collision de nom de service : "${objectName}" porte plusieurs définitions`);
    }
    newServices.set(objectName, normalized);
  };

  for (const p of selectedPolicies) {
    const { analysis } = p;
    const selections = p.addressSelections || p._addressSelections || {};
    if (p._serverPolicyBinding !== true
      && ((p._srcCidrOverride && !(selections.source || selections.src))
        || (p._dstCidrOverride && !(selections.destination || selections.dst)))) {
      throw new Error(`Policy "${p.policyName || p.name || p.id || '?'}" : override CIDR sans sélection d’adresse confirmée`);
    }
    if (!analysis || !Array.isArray(analysis.services)) {
      throw new Error(`Policy "${p.policyName || p.name || p.id || '?'}" sans analyse de services — génération refusée`);
    }

    // Source address(es) — peut être multiple si policy-grouped merge
    let srcAddrName, srcAddrNames, srcAddrGrpName;
    if (p._srcCidrOverride && !p._use32Src) {
      // B: masque custom choisi par l'ingénieur (mode subnet uniquement) → objet adresse avec ce CIDR exact
      const cidr = p._srcCidrOverride;
      const name = p._srcAddrName || suggestAddrName(cidr, NP);
      registerGeneratedAddress(cidr, name);
      srcAddrName = name;
    } else if (p._multiSrcSubnets?.length > 0) {
      // ── Multi-src subnets : per-subnet /24 vs /32 (like _multiDstSubnets) ──
      const allSrcNames = [];
      for (const s of p._multiSrcSubnets) {
        if (s.useSubnet !== false) {
          // /24 mode: use subnet address
          if (s.addrFound) {
            allSrcNames.push(s.addrName);
          } else {
            const name = s.addrName || suggestAddrName(s.subnet, NP);
            allSrcNames.push(name);
            registerGeneratedAddress(s.subnet, name);
          }
        } else {
          // /32 mode: list individual hosts
          for (const h of (s.hosts || [])) {
            const { name, isNew } = resolveHost32(h, p._srcHostNames);
            if (isNew) registerGeneratedAddress(`${h}/32`, name);
            allSrcNames.push(name);
          }
        }
      }
      srcAddrNames = allSrcNames;
      if (p._useSrcGroup) {
        srcAddrGrpName = registerAddrGroup(newAddrGroups,
          p._srcAddrName || `${NP}_GRP_SRC_${suggestAddrName(p._multiSrcSubnets[0].subnet, NP)}`, allSrcNames);
      }
    } else if (p._isSvcMerge && p._mergedSrcSubnets && p._mergedSrcSubnets.length > 1) {
      // Fusion par service : créer un groupe d'adresses pour les sources fusionnées
      const subnetNames = p._mergedSrcSubnets.map(s => suggestAddrName(s, NP));
      p._mergedSrcSubnets.forEach((cidr, i) => registerGeneratedAddress(cidr, subnetNames[i]));
      srcAddrNames = subnetNames;
      srcAddrGrpName = registerAddrGroup(newAddrGroups,
        p._srcAddrName || `${NP}_SVC_GRP_${suggestAddrName(p._mergedSrcSubnets[0], NP)}`, subnetNames);
    } else if (p._use32Src && p.srcHosts && p.srcHosts.length > 0) {
      // Mode /32 : utiliser les hôtes réels plutôt que le subnet /24
      const hostNames = p.srcHosts.map(h => {
        const { name, isNew } = resolveHost32(h, p._srcHostNames);
        if (isNew) registerGeneratedAddress(`${h}/32`, name);
        return name;
      });
      if (hostNames.length === 1) {
        srcAddrName = hostNames[0];
      } else if (p._useSrcGroup) {
        // Utilisateur a demandé un groupe
        srcAddrNames = hostNames;
        srcAddrGrpName = registerAddrGroup(newAddrGroups,
          p.srcAddrName || `${NP}_HOSTS_${suggestAddrName(p.srcSubnet, NP)}`, hostNames);
      } else {
        // Par défaut : lister inline dans set srcaddr
        srcAddrName = hostNames;
      }
    } else if (p.srcAddrNames && p.srcAddrNames.length > 1 && !p._multiSrcSubnets) {
      // Multi-src legacy : enregistrer chaque adresse + créer un groupe
      srcAddrNames = p.srcAddrNames;
      const subnets = p.srcSubnets || [p.srcSubnet];
      subnets.forEach((cidr, i) => {
        const name = p.srcAddrNames[i] || suggestAddrName(cidr, NP);
        registerGeneratedAddress(cidr, name);
      });
      // Créer un groupe d'adresses
      srcAddrGrpName = registerAddrGroup(newAddrGroups,
        p.srcAddrName || p.policyName || `${NP}_GRP_${suggestAddrName(subnets[0], NP)}`, srcAddrNames);
    } else if (p._srcAddrGrpFound) {
      // Groupe existant trouvé → l'utiliser directement
      srcAddrName = p.srcAddrName || p._srcAddrName;
    } else if (analysis.srcAddr.found) {
      srcAddrName = analysis.srcAddr.name;
    } else {
      srcAddrName = p.srcAddrName || suggestAddrName(analysis.srcAddr.cidr, NP);
      registerGeneratedAddress(analysis.srcAddr.cidr, srcAddrName);
    }

    // Destination address
    let dstAddrName;
    // B: masque custom dst (LAN uniquement) → objet adresse avec ce CIDR exact
    if (p._dstCidrOverride && !p._use32Dst && !(p._isWan || p.dstType === 'public')) {
      const cidr = p._dstCidrOverride;
      const name = p._dstAddrName || suggestAddrName(cidr, NP);
      registerGeneratedAddress(cidr, name);
      dstAddrName = name;
    // ── WAN policy : "all" uniquement sur choix explicite ──
    } else if ((p._isWan || p.dstType === 'public') && p._dstUseAll === true) {
      dstAddrName = 'all';
    } else if ((p._isWan || p.dstType === 'public')
        && !p._use32Dst
        && (p._dstCidrOverride || p._dstAddrName || (p._dstMode === 'subnet' && p.analysis?.dstAddr?.found))) {
      // A confirmed WAN subnet/object selection is server-applied before generation.
      if (p._dstAddrName && p.analysis?.dstAddr?.found) {
        dstAddrName = p._dstAddrName;
      } else if (p._dstCidrOverride) {
        const cidr = p._dstCidrOverride;
        const name = p._dstAddrName || p.dstAddrName || suggestAddrName(cidr, NP);
        registerGeneratedAddress(cidr, name);
        dstAddrName = name;
      } else {
        throw new Error(`Policy WAN "${p.policyName || p.name || p.id || '?'}" sans destination réseau sélectionnée`);
      }
    } else if (p._isWan || p.dstType === 'public') {
      // Mode sûr par défaut : conserver exactement les destinations WAN observées.
      if (p._isMultiDst && p._multiDstSubnets?.length > 0) {
        const hosts = [...new Set([
          ...(p.dstHosts || []),
          ...p._multiDstSubnets.flatMap(s => s.hosts || []),
        ])];
        if (!hosts.length) {
          throw new Error(`Policy WAN "${p.policyName || p.name || p.id || '?'}" sans destination spécifique — génération refusée`);
        }
        const hostNames = hosts.map(h => {
          const { name, isNew } = resolveHost32(h, p._dstHostNames);
          if (isNew) registerGeneratedAddress(`${h}/32`, name);
          return name;
        });
        dstAddrName = hostNames.length === 1 ? hostNames[0] : hostNames;
      } else if (p._use32Dst && p.dstHosts?.length > 0) {
        const hostNames = p.dstHosts.map(h => {
          const { name, isNew } = resolveHost32(h, p._dstHostNames);
          if (isNew) registerGeneratedAddress(`${h}/32`, name);
          return name;
        });
        dstAddrName = hostNames.length === 1 ? hostNames[0] : hostNames;
      } else if (p.dstHosts?.length > 0) {
        const hostNames = p.dstHosts.map(h => {
          const { name, isNew } = resolveHost32(h, p._dstHostNames);
          if (isNew) registerGeneratedAddress(`${h}/32`, name);
          return name;
        });
        dstAddrName = hostNames.length === 1 ? hostNames[0] : hostNames;
      } else if (p.dstTarget && p.dstTarget !== 'all') {
        const ip = p.dstTarget;
        const cidr = ip.includes('/') ? ip : `${ip}/32`;
        const name = p._dstAddrName || p.dstAddrName || suggestAddrName(cidr, NP);
        registerGeneratedAddress(cidr, name);
        dstAddrName = name;
      } else {
        throw new Error(`Policy WAN "${p.policyName || p.name || p.id || '?'}" sans destination spécifique — génération refusée`);
      }
    // ── Multi-dst : "all" si _dstUseAll=true ──
    } else if (p._isMultiDst && p._dstUseAll === true) {
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
            const name = s.addrName || suggestAddrName(s.subnet, NP);
            dstNames.push(name);
            registerGeneratedAddress(s.subnet, name);
          }
        } else {
          // /32 mode: list individual hosts
          for (const h of (s.hosts || [])) {
            const { name, isNew } = resolveHost32(h, p._dstHostNames);
            if (isNew) registerGeneratedAddress(`${h}/32`, name);
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
        if (isNew) registerGeneratedAddress(`${h}/32`, name);
        return name;
      });
      // On stocke comme tableau pour que le serialiseur génère plusieurs valeurs
      dstAddrName = hostNames.length === 1 ? hostNames[0] : hostNames;
    } else if (analysis.dstAddr.found) {
      dstAddrName = analysis.dstAddr.name;
    } else {
      dstAddrName = p.dstAddrName || suggestAddrName(analysis.dstAddr.cidr, NP);
      if (dstAddrName !== 'all') registerGeneratedAddress(analysis.dstAddr.cidr, dstAddrName);
    }

    // Services
    const serviceNames = [];
    for (const svc of analysis.services) {
      if (svc.found) {
        if (!svc.name) {
          throw new Error(`Service résolu sans nom dans la policy "${p.policyName || p.name || p.id || '?'}"`);
        }
        serviceNames.push(svc.name);
      } else {
        const customName = p.serviceNames?.[svc.label] || svc.suggestedName;
        if (!customName) {
          throw new Error(`Service "${svc.label || '?'}" sans nom ni définition exacte — génération refusée`);
        }
        serviceNames.push(customName);
        // Si port/proto absents mais label au format TCP/5010 ou UDP/53, les extraire
        let resolvedPort  = svc.port;
        let resolvedProto = svc.proto;
        if (!resolvedPort && !svc.ports?.length && !svc.portRange) {
          const labelMatch = /^(TCP|UDP)\/(\d+)$/i.exec(svc.label || '');
          if (labelMatch) { resolvedProto = labelMatch[1].toUpperCase(); resolvedPort = parseInt(labelMatch[2], 10); }
        }

        if (svc.tcpPorts?.length || svc.udpPorts?.length) {
          registerGeneratedService(customName, {
            tcpPorts: svc.tcpPorts || [],
            udpPorts: svc.udpPorts || [],
          });
        } else if (svc.ports?.length) {
          registerGeneratedService(customName, { ports: svc.ports, proto: svc.proto });
        } else if (svc.portRange) {
          registerGeneratedService(customName, { portRange: svc.portRange, proto: svc.proto });
        } else if (resolvedPort) {
          registerGeneratedService(customName, {
            port: resolvedPort, proto: resolvedProto,
          });
        } else {
          throw new Error(`Service "${svc.label || customName}" sans protocole/port exact — génération refusée`);
        }
      }
    }
    if (serviceNames.length === 0) {
      throw new Error(`Policy "${p.policyName || p.name || p.id || '?'}" sans service — génération de ALL refusée`);
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
      action:      p.action || p._action || actionVerb,
      log:         p.log || p._log || logTraffic,
      securityProfiles: p.securityProfiles || p._secProfiles || null,
      tags:        p.tags || p._tags || [],
      disabled:    p.disabled ?? p._disabled ?? false,
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
  if (target === 'fmg-script') {
    // #9: en-tête pour exécution en tant que script FortiManager sur un Policy Package.
    // Le contenu est du CLI FortiOS standard (config firewall …), exécuté dans le contexte
    // de l'ADOM/Policy Package — PAS de wrapper `config adom`, PAS de syntaxe device-DB.
    L.push('# ══════════════════════════════════════════════════');
    L.push('# Script FortiManager — à exécuter sur un Policy Package');
    L.push('# ──────────────────────────────────────────────────');
    L.push('# Mode opératoire :');
    L.push('#  1. FortiManager > Policy & Objects > (sélectionner l\'ADOM)');
    L.push('#  2. CLI Scripts > Create New : "Run script on" = "Policy Package or ADOM Database"');
    L.push('#  3. Coller ce script, sélectionner le Policy Package cible, exécuter');
    L.push('#  4. Lancer l\'Install Wizard pour pousser vers les FortiGate');
    L.push('# Note : les policies utilisent "edit 0" → FortiManager attribue les policyid.');
    L.push('# ══════════════════════════════════════════════════');
    L.push('');
  }
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
      const proto = String(svc.proto || '').toUpperCase();
      const isUdp = proto === 'UDP' || proto === '17';
      const isTcp = !isUdp;
      const portrangeVal = svc.portRange || (svc.ports?.length ? consolidatePortRanges(svc.ports) : String(svc.port || ''));
      const tcpRange = svc.tcpPorts?.length ? consolidatePortRanges(svc.tcpPorts) : (isTcp ? portrangeVal : '');
      const udpRange = svc.udpPorts?.length ? consolidatePortRanges(svc.udpPorts) : (isUdp ? portrangeVal : '');
      if (!tcpRange && !udpRange) {
        throw new Error(`Service "${svc.name}" sans plage TCP/UDP valide — génération refusée`);
      }
      L.push(`    edit "${safeCli(svc.name)}"`);
      L.push(`        set protocol TCP/UDP/SCTP`);
      if (tcpRange) L.push(`        set tcp-portrange ${tcpRange}`);
      if (udpRange) L.push(`        set udp-portrange ${udpRange}`);
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
        if (sp.profileGroup) {
          L.push('        set profile-type group');
          L.push(`        set profile-group "${safeCli(sp.profileGroup)}"`);
        } else {
          if (sp.antivirus) L.push(`        set av-profile "${safeCli(sp.antivirus)}"`);
          if (sp.webfilter) L.push(`        set webfilter-profile "${safeCli(sp.webfilter)}"`);
          if (sp.ips) L.push(`        set ips-sensor "${safeCli(sp.ips)}"`);
          if (sp.sslSsh) L.push(`        set ssl-ssh-profile "${safeCli(sp.sslSsh)}"`);
        }
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

function segmentationServiceKey(service) {
  if (!service) return '';
  return String(service.label || service.name || '').toUpperCase();
}

function sameServiceLabelScope(requestedServices, recalculatedServices) {
  const labels = services => [...new Set((services || [])
    .map(segmentationServiceKey)
    .filter(Boolean))].sort();
  const requested = labels(requestedServices);
  const recalculated = labels(recalculatedServices);
  return requested.length === recalculated.length
    && requested.every((label, index) => label === recalculated[index]);
}

function segmentationProto(proto) {
  if (/^(6|tcp)$/i.test(String(proto || ''))) return 'TCP';
  if (/^(17|udp)$/i.test(String(proto || ''))) return 'UDP';
  return String(proto || '').toUpperCase();
}

function segmentationFlowServiceKey(flow) {
  const named = String(flow?.service || '').trim();
  if (named) return named.toUpperCase();
  const port = Number(flow?.dstport ?? flow?.port);
  const proto = segmentationProto(flow?.proto);
  return Number.isInteger(port) && proto ? `${port}/${proto}` : '';
}

function segmentationFlowTechnicalKey(flow) {
  const port = Number(flow?.dstport ?? flow?.port);
  const rawProto = String(flow?.proto || '').trim().toUpperCase();
  const proto = /^(6|tcp)$/i.test(rawProto) ? 'TCP'
    : /^(17|udp)$/i.test(rawProto) ? 'UDP'
      : /^(1|icmp)$/i.test(rawProto) ? 'ICMP'
        : rawProto ? `PROTO-${rawProto}` : 'PROTO-UNKNOWN';
  if (proto === 'ICMP') {
    if (Number.isInteger(flow?.icmpType) && Number.isInteger(flow?.icmpCode)) {
      return `ICMP:${flow.icmpType}:${flow.icmpCode}`;
    }
    const label = String(flow?.service || '').trim().toUpperCase();
    const icmp = label.match(/^ICMP\/(\d+)\/(\d+)$/);
    if (icmp) return `ICMP:${Number(icmp[1])}:${Number(icmp[2])}`;
    if (label && !['ICMP', 'ALL_ICMP', 'ALL_ICMP6'].includes(label)) return `ICMP:NAME:${label}`;
  }
  return ['TCP', 'UDP'].includes(proto) && Number.isInteger(port) && port >= 1
    ? `${proto}:${port}`
    : proto;
}

function segmentationServiceMatchesTuple(service, tuple) {
  const wanted = segmentationServiceKey(service);
  const named = String(tuple?.service || '').toUpperCase();
  if (wanted && named && wanted === named) return true;

  const port = Number(tuple?.port ?? tuple?.dstport);
  const proto = segmentationProto(tuple?.proto);
  if (!Number.isInteger(port) || !proto) return false;

  const directPort = Number(service?.port);
  if (Number.isInteger(directPort) && directPort === port) {
    return !service.proto || segmentationProto(service.proto) === proto;
  }

  const notation = wanted.match(/^(?:(TCP|UDP)\/(\d+)|(\d+)\/(TCP|UDP))$/);
  if (notation) {
    return (notation[1] || notation[4]) === proto
      && Number(notation[2] || notation[3]) === port;
  }

  const ports = Array.isArray(service?.ports) ? service.ports.map(Number) : [];
  return ports.includes(port) && (!service.proto || segmentationProto(service.proto) === proto);
}

function segmentationFlowAllowed(flow) {
  if (String(flow?.decision || '').toLowerCase() === 'allow') return true;
  return new Set(['accept', 'allow', 'allowed', 'pass', 'start', 'close', 'timeout', 'client-rst', 'server-rst', 'ip-conn'])
    .has(String(flow?.action || '').toLowerCase());
}

function segmentationFlowInScope(flow, policy) {
  const scope = policy.scope || {};
  const flowVdom = flow.vdom || flow.vd || '';
  const flowDevice = flow.devid || flow.devname || '';
  const policyDevice = scope.devid || scope.devname || '';
  if (scope.vdom && flowVdom && scope.vdom !== flowVdom) return false;
  if (policyDevice && flowDevice && policyDevice !== flowDevice) return false;
  return true;
}

function segmentationEvidenceHosts(policy, side) {
  const hosts = side === 'src' ? policy.srcHosts : policy.dstHosts;
  if (Array.isArray(hosts) && hosts.length) return [...new Set(hosts.filter(Boolean))];
  const cidr = side === 'src' ? policy.srcSubnet : policy.dstTarget;
  const match = String(cidr || '').match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/32)?$/);
  return match ? [match[1]] : [];
}

function policyEngineSelectionMetrics(requiredAtoms, selectedPolicies) {
  const key = (partitionKey, source, destination, serviceKey) =>
    [partitionKey, source, destination, serviceKey].join('||');
  const required = new Set((requiredAtoms || [])
    .filter(atom => atom?.service?.deploymentBlocked !== true)
    .map(atom => key(atom.partitionKey, atom.source, atom.destination, atom.service.key)));
  const allowed = new Set();
  for (const policy of (selectedPolicies || [])) {
    for (const source of (policy.allowedSources || policy.sources || [])) {
      for (const destination of (policy.allowedDestinations || policy.destinations || [])) {
        for (const serviceKey of (policy.serviceKeys || [])) {
          allowed.add(key(policy.partitionKey, source, destination, serviceKey));
        }
      }
    }
  }
  let coveredRequiredTuples = 0;
  for (const tuple of required) if (allowed.has(tuple)) coveredRequiredTuples++;
  let unexpectedAllowedTuples = 0;
  for (const tuple of allowed) if (!required.has(tuple)) unexpectedAllowedTuples++;
  const missingRequiredTuples = required.size - coveredRequiredTuples;
  return {
    observedRequiredTuples: required.size,
    coveredRequiredTuples,
    missingRequiredTuples,
    allowedTuples: allowed.size,
    unexpectedAllowedTuples,
    coverageRatio: required.size ? coveredRequiredTuples / required.size : 1,
    expansionRatio: required.size ? unexpectedAllowedTuples / required.size : 0,
  };
}

function preflightValidation(selectedPolicies, config, observedFlows = null, requiredAtoms = null) {
  const issues = []; // { level: 'warn'|'error', msg }
  const addresses      = config.addresses      || {};
  const addressGroups  = config.addressGroups   || {};
  const interfaces     = config.interfaces      || {};
  const zones          = config.zones           || {};

  const namesUsed = new Map(); // name → [policy indices]
  const selectedScopes = new Set();
  let exactScopePolicies = 0;
  let generalizedPolicies = 0;
  let unclassifiedPolicies = 0;
  const routingContextUnproven = Boolean(config.hasPolicyRoutes || config.hasSdwanRules);
  const addressSelectionValidation = validatePolicyAddressSelections(selectedPolicies, config);
  issues.push(...addressSelectionValidation.issues);

  if (config.hasNonDefaultVrf) {
    issues.push({
      level: 'error',
      code: 'VRF_CONTEXT',
      msg: 'VRF non par défaut détectée : sélection de table VRF requise avant génération',
    });
  }
  if (routingContextUnproven) {
    const contexts = [
      config.hasPolicyRoutes ? 'PBR' : '',
      config.hasSdwanRules ? 'règles SD-WAN' : '',
    ].filter(Boolean).join(' et ');
    issues.push({
      level: 'warn',
      code: 'ROUTING_CONTEXT_UNPROVEN',
      msg: `${contexts} détecté(s) : les interfaces observées restent utilisables, mais le chemin ne peut pas être certifié uniquement avec la table de routage`,
    });
  }

  for (let i = 0; i < selectedPolicies.length; i++) {
    const p = selectedPolicies[i];
    const a = p.analysis || {};
    const label = `Policy #${i + 1}`;

    // Interfaces : accepter les champs bruts et ceux résolus par l'analyse.
    const srcValue = p.srcintf || p._srcintf || a.srcZone || a.srcIface;
    const dstValue = p.dstintf || p._dstintf || a.dstZone || a.dstIface;
    const srcIntfs = (Array.isArray(srcValue) ? srcValue : [srcValue]).filter(Boolean);
    const dstIntfs = (Array.isArray(dstValue) ? dstValue : [dstValue]).filter(Boolean);
    if (!srcIntfs.length) issues.push({ level: 'error', msg: `${label}: interface source manquante` });
    if (!dstIntfs.length) issues.push({ level: 'error', msg: `${label}: interface destination manquante` });
    if (srcIntfs.some(name => dstIntfs.includes(name))) {
      issues.push({ level: 'warn', msg: `${label}: même interface présente en source et destination — hairpin` });
    }

    // Une interface absente n'est pas un simple avertissement : la CLI serait invalide.
    for (const srcIntf of srcIntfs) {
      if (!interfaces[srcIntf] && !zones[srcIntf]) {
        issues.push({ level: 'error', msg: `${label}: interface source "${srcIntf}" absente de la config` });
      }
    }
    for (const dstIntf of dstIntfs) {
      if (!interfaces[dstIntf] && !zones[dstIntf]) {
        issues.push({ level: 'error', msg: `${label}: interface destination "${dstIntf}" absente de la config` });
      }
    }

    const action = String(p.action || p._action || 'accept').toLowerCase();
    if (!['accept', 'deny'].includes(action)) {
      issues.push({ level: 'error', msg: `${label}: action FortiGate invalide "${action}"` });
    }
    const logMode = String(p.log || p._log || 'all').toLowerCase();
    if (!['all', 'utm', 'disable'].includes(logMode)) {
      issues.push({ level: 'error', msg: `${label}: mode logtraffic invalide "${logMode}"` });
    }

    const scope = p.scope || {};
    const scopeKey = `${scope.devid || scope.devname || ''}::${scope.vdom || ''}`;
    if (scope.devid || scope.devname || scope.vdom) selectedScopes.add(scopeKey);
    if (scope.vdom && config.selectedVdom && scope.vdom !== config.selectedVdom) {
      issues.push({ level: 'error', msg: `${label}: flux du VDOM "${scope.vdom}" incompatible avec la config "${config.selectedVdom}"` });
    }

    const isWan = p._isWan || p.dstType === 'public';
    if (isWan && p._dstUseAll !== true) {
      const hasSpecificDst = (p.dstHosts || []).length > 0
        || (p._multiDstSubnets || []).some(s => (s.hosts || []).length > 0)
        || (p.dstTarget && p.dstTarget !== 'all');
      if (!hasSpecificDst) {
        issues.push({ level: 'error', msg: `${label}: destination WAN spécifique manquante` });
      }
    }
    if (isWan && p._dstUseAll === true) {
      issues.push({ level: 'warn', msg: `${label}: destination WAN explicitement élargie à "all"` });
    }

    if (!(a.services || []).length) {
      issues.push({ level: 'error', msg: `${label}: aucun service déterminé — génération de ALL refusée` });
    }
    const srcNameValues = [
      p._srcAddrName,
      p.srcAddrName,
      a.srcAddr?.name,
      ...(p.srcAddrNames || []),
    ].filter(Boolean).map(value => String(value).toUpperCase());
    if (action === 'accept' && srcNameValues.includes('ALL')) {
      issues.push({ level: 'error', msg: `${label}: srcaddr=all interdit pour une règle accept générée` });
    }
    const broadServiceNames = (a.services || [])
      .map(service => String(service.name || service.label || '').toUpperCase())
      .filter(name => ['ALL', 'ALL_TCP', 'ALL_UDP', 'ALL_ICMP', 'ALL_ICMP6'].includes(name));
    if (action === 'accept' && broadServiceNames.length) {
      issues.push({ level: 'error', msg: `${label}: service global interdit (${broadServiceNames.join(', ')})` });
    }
    for (const service of (a.services || [])) {
      if (service.found) continue;
      const validPorts = values => Array.isArray(values)
        && values.length > 0
        && values.every(value => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 65535);
      const hasExactTransport = validPorts(service.tcpPorts)
        || validPorts(service.udpPorts)
        || (validPorts(service.ports) && ['TCP', 'UDP', '6', '17'].includes(String(service.proto || '').toUpperCase()))
        || (Number.isInteger(Number(service.port))
          && Number(service.port) >= 1
          && Number(service.port) <= 65535
          && ['TCP', 'UDP', '6', '17'].includes(String(service.proto || '').toUpperCase()))
        || (/^\d+(?:-\d+)?(?:\s+\d+(?:-\d+)?)*$/.test(String(service.portRange || ''))
          && ['TCP', 'UDP', '6', '17'].includes(String(service.proto || '').toUpperCase()));
      if (!hasExactTransport) {
        issues.push({
          level: 'error',
          msg: `${label}: service "${service.label || service.name || '?'}" non résolu et sans définition protocole/port exacte`,
        });
      }
    }

    const plan = p._segmentationPlan;
    if (plan) {
      const validSource = ['network', 'host'].includes(plan.source);
      const validDestination = ['network', 'host'].includes(plan.destination);
      const validServices = ['grouped', 'separate'].includes(plan.services);
      if (!validSource || !validDestination || !validServices) {
        issues.push({ level: 'error', msg: `${label}: plan de segmentation invalide` });
      }

      const expectedServices = a.services || [];
      const expectedKeys = new Set(expectedServices.map(segmentationServiceKey).filter(Boolean));
      const technicalServices = (p.services || []).map(value => String(value).toUpperCase());
      const unexpectedTechnical = technicalServices.filter(value => !expectedKeys.has(value));
      if (unexpectedTechnical.length) {
        issues.push({
          level: 'error',
          msg: `${label}: services techniques hors périmètre (${unexpectedTechnical.join(', ')})`,
        });
      }

      const unexpectedTuples = (p.serviceTuples || []).filter(tuple =>
        !expectedServices.some(service => segmentationServiceMatchesTuple(service, tuple))
      );
      if (unexpectedTuples.length) {
        issues.push({
          level: 'error',
          msg: `${label}: tuples protocole/port hors du service sélectionné`,
        });
      }

      if (plan.services === 'separate' && expectedServices.length !== 1) {
        issues.push({ level: 'error', msg: `${label}: le mode "un service par règle" exige exactement un service` });
      }

      const effectiveDestinationMode = isWan ? 'host' : plan.destination;
      const v2SafeExact = p._policyEngineV2?.safeExact === true;
      const exactScope = v2SafeExact || (plan.source === 'host'
        && effectiveDestinationMode === 'host'
        && plan.services === 'separate');
      if (exactScope) exactScopePolicies++;
      else generalizedPolicies++;
      const srcEvidenceHosts = segmentationEvidenceHosts(p, 'src');
      const dstEvidenceHosts = segmentationEvidenceHosts(p, 'dst');
      if (plan.source === 'host' && (!p._use32Src || !srcEvidenceHosts.length)) {
        issues.push({ level: 'error', msg: `${label}: source /32 exigée mais aucune source exacte n'est disponible` });
      }
      if (effectiveDestinationMode === 'host' && (!p._use32Dst || !dstEvidenceHosts.length)) {
        issues.push({ level: 'error', msg: `${label}: destination /32 exigée mais aucune destination exacte n'est disponible` });
      }
      if (p._hpsUnverified) {
        issues.push({ level: 'error', msg: `${label}: règle détaillée non prouvée par une paire de flux observée` });
      }

      if (Array.isArray(observedFlows)) {
        const srcSet = new Set(srcEvidenceHosts);
        const dstSet = new Set(dstEvidenceHosts);
        const evidenceFlows = observedFlows.filter(flow =>
          segmentationFlowAllowed(flow)
          && segmentationFlowInScope(flow, p)
          && srcSet.has(flow.srcip)
          && dstSet.has(flow.dstip)
        );

        if (!evidenceFlows.length) {
          issues.push({ level: 'error', msg: `${label}: aucun flux accepté ne prouve cette règle` });
        } else if (v2SafeExact) {
          for (const src of srcEvidenceHosts) {
            for (const dst of dstEvidenceHosts) {
              for (const serviceKey of (p.serviceKeys || [])) {
                if (!evidenceFlows.some(flow =>
                  flow.srcip === src && flow.dstip === dst && segmentationFlowTechnicalKey(flow) === serviceKey
                )) {
                  issues.push({
                    level: 'error',
                    msg: `${label}: couple ${src} → ${dst} / ${serviceKey} non observé`,
                  });
                }
              }
            }
          }
        } else if (plan.source === 'host' && effectiveDestinationMode === 'host' && (p.serviceTuples || []).length) {
          const technicalKeys = [...new Set((p.serviceTuples || [])
            .map(segmentationFlowTechnicalKey)
            .filter(Boolean))];
          for (const src of srcEvidenceHosts) {
            for (const dst of dstEvidenceHosts) {
              for (const serviceKey of technicalKeys) {
                if (!evidenceFlows.some(flow =>
                  flow.srcip === src && flow.dstip === dst && segmentationFlowTechnicalKey(flow) === serviceKey
                )) {
                  issues.push({
                    level: 'error',
                    msg: `${label}: couple ${src} → ${dst} / ${serviceKey} non observé`,
                  });
                }
              }
            }
          }
        } else if (plan.source === 'host' && effectiveDestinationMode === 'host') {
          for (const src of srcEvidenceHosts) {
            for (const dst of dstEvidenceHosts) {
              for (const service of expectedServices) {
                const wanted = segmentationServiceKey(service);
                if (!evidenceFlows.some(flow =>
                  flow.srcip === src && flow.dstip === dst && segmentationFlowServiceKey(flow) === wanted
                )) {
                  issues.push({
                    level: 'error',
                    msg: `${label}: couple ${src} → ${dst} / ${wanted || 'service inconnu'} non observé`,
                  });
                }
              }
            }
          }
        } else {
          for (const service of expectedServices) {
            const wanted = segmentationServiceKey(service);
            if (!evidenceFlows.some(flow => segmentationFlowServiceKey(flow) === wanted)) {
              issues.push({
                level: 'error',
                msg: `${label}: service ${wanted || 'inconnu'} absent des flux acceptés dans ce périmètre`,
              });
            }
          }
        }
      }
    } else {
      unclassifiedPolicies++;
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

  if (selectedScopes.size > 1) {
    issues.push({ level: 'error', msg: 'Plusieurs équipements/VDOM sont mélangés dans la même génération' });
  }

  // Detect duplicates
  for (const [, indices] of namesUsed) {
    if (indices.length > 1) {
      issues.push({ level: 'warn', msg: `Policies #${indices.join(', #')} sont des doublons potentiels (mêmes src/dst/services)` });
    }
  }

  if (generalizedPolicies > 0) {
    issues.push({
      level: 'warn',
      code: 'GENERALIZED_SCOPE',
      msg: `${generalizedPolicies} policy(s) utilisent un périmètre réseau ou des services regroupés : elles sont validées comme généralisation choisie, pas comme correspondance exacte aux seuls tuples observés`,
    });
  }
  if (unclassifiedPolicies > 0) {
    issues.push({
      level: 'warn',
      code: 'UNCLASSIFIED_SCOPE',
      msg: `${unclassifiedPolicies} policy(s) ne portent aucun plan de segmentation certifiable`,
    });
  }

  let selectionMetrics = null;
  const v2Policies = selectedPolicies.filter(policy => policy?._policyEngineV2);
  if (v2Policies.length > 0 && Array.isArray(requiredAtoms)) {
    selectionMetrics = policyEngineSelectionMetrics(requiredAtoms, v2Policies);
    if (selectionMetrics.missingRequiredTuples > 0) {
      issues.push({
        level: 'error',
        code: 'POLICY_ENGINE_MISSING_REQUIRED_TUPLES',
        msg: `${selectionMetrics.missingRequiredTuples} tuple(s) déployable(s) requis ne sont plus couverts par la sélection finale`,
      });
    }
    const safeProfile = v2Policies.every(policy =>
      ['recommended', 'strict', 'expert'].includes(policy._policyEngineV2.profile)
    );
    if (safeProfile && selectionMetrics.unexpectedAllowedTuples > 0) {
      issues.push({
        level: 'error',
        code: 'POLICY_ENGINE_UNEXPECTED_ALLOWED_TUPLES',
        msg: `${selectionMetrics.unexpectedAllowedTuples} tuple(s) inattendu(s) sont autorisés par la sélection finale`,
      });
    }
  }

  // Summary counts
  const errors   = issues.filter(i => i.level === 'error').length;
  const warnings = issues.filter(i => i.level === 'warn').length;
  const certification = {
    level: errors > 0 ? 'rejected'
      : routingContextUnproven ? 'conditional'
        : (generalizedPolicies > 0 || unclassifiedPolicies > 0) ? 'generalized'
        : 'exact',
    exactPolicies: exactScopePolicies,
    generalizedPolicies,
    unclassifiedPolicies,
    routingContextUnproven,
  };
  return { issues, errors, warnings, ok: errors === 0, certification, selectionMetrics };
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
  ip2int,
  int2ip,
  networkAddress,
  findPredefinedService,
  parseFortiConfig,
  analyzePolicies,
  validatePolicyAddressSelections,
  applyPolicyAddressSelections,
  generateConfig,
  validateAgainstExisting,
  preflightValidation,
  policyEngineSelectionMetrics,
  sameServiceLabelScope,
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
  resolveInterfaceByRoute,
  formatExistingPolicies,
};

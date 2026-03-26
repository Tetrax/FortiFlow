// Résolution des noms de ports courants (TCP + UDP)
// Usage : portName(port, proto) → 'HTTPS' | ''

const TCP = new Map([
  [20, 'FTP-DATA'],  [21, 'FTP'],       [22, 'SSH'],        [23, 'TELNET'],
  [25, 'SMTP'],      [53, 'DNS'],        [80, 'HTTP'],       [88, 'KERBEROS'],
  [110, 'POP3'],     [111, 'SUNRPC'],    [119, 'NNTP'],      [135, 'MSRPC'],
  [139, 'NETBIOS'],  [143, 'IMAP'],      [179, 'BGP'],       [389, 'LDAP'],
  [443, 'HTTPS'],    [445, 'SMB'],       [465, 'SMTPS'],     [514, 'SYSLOG'],
  [515, 'LPD'],      [587, 'SMTP-SUB'],  [636, 'LDAPS'],     [993, 'IMAPS'],
  [995, 'POP3S'],    [1080, 'SOCKS'],    [1194, 'OPENVPN'],  [1433, 'MSSQL'],
  [1434, 'MSSQL-M'], [1521, 'ORACLE'],   [1723, 'PPTP'],     [2049, 'NFS'],
  [2181, 'ZOOKEEPER'],[2375, 'DOCKER'],  [2376, 'DOCKER-TLS'],[3000, 'HTTP-ALT'],
  [3268, 'LDAP-GC'], [3306, 'MYSQL'],    [3389, 'RDP'],      [3690, 'SVN'],
  [4369, 'EPMD'],    [5000, 'HTTP-ALT'], [5432, 'PGSQL'],    [5672, 'AMQP'],
  [5900, 'VNC'],     [5985, 'WINRM'],    [5986, 'WINRM-TLS'],[6379, 'REDIS'],
  [6443, 'K8S-API'], [7001, 'WEBLOGIC'], [8000, 'HTTP-ALT'], [8080, 'HTTP-PROXY'],
  [8443, 'HTTPS-ALT'],[8888, 'HTTP-ALT'],[9000, 'HTTP-ALT'], [9090, 'HTTP-ALT'],
  [9092, 'KAFKA'],   [9200, 'ELASTIC'],  [9300, 'ELASTIC-T'], [10250, 'KUBELET'],
  [11211, 'MEMCACHE'],[15672, 'RABBITMQ'],[27017, 'MONGODB'], [27018, 'MONGODB'],
  [49152, 'WINRPC'],
]);

const UDP = new Map([
  [53, 'DNS'],    [67, 'DHCP-S'],  [68, 'DHCP-C'],  [69, 'TFTP'],
  [123, 'NTP'],   [137, 'NBNS'],   [138, 'NBDG'],    [161, 'SNMP'],
  [162, 'SNMPT'], [500, 'IKE'],    [514, 'SYSLOG'],  [520, 'RIP'],
  [1194, 'OPENVPN'],[1701, 'L2TP'],[4500, 'IPSEC'],  [5353, 'MDNS'],
]);

/**
 * Retourne le nom du port ou une chaîne vide.
 * @param {string|number} port
 * @param {string} proto  — 'TCP', 'UDP', '6', '17', ou vide
 */
function portName(port, proto) {
  const p = parseInt(port, 10);
  if (isNaN(p)) return '';
  const protoUp = String(proto || '').toUpperCase();
  if (protoUp === 'UDP' || protoUp === '17') return UDP.get(p) || '';
  // TCP par défaut (proto 6 ou vide)
  return TCP.get(p) || '';
}

module.exports = { portName, TCP, UDP };

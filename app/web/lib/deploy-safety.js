'use strict';

function getCaptureDeploymentBlockers(sessionData, fortiConfig = null) {
  const data = sessionData || {};
  const unsupportedIpv6 = Number(data.meta?.skipReasons?.ipv6 || 0);
  const invalidFlowRecords = Number(data.meta?.skipReasons?.invalidFlow || 0);
  const archiveEntryErrors = Number(data.meta?.skipReasons?.archiveEntryError || 0);
  const unknownActionSessions = Number(data.stats?.unknownSessions || 0);
  const failedConnectionSessions = Number(data.stats?.failedSessions || 0);
  const allowActions = new Set([
    'accept', 'allow', 'allowed', 'pass', 'close', 'timeout',
    'client-rst', 'server-rst', 'ip-conn',
  ]);
  const legacyUnprovenSessions = (data.flows || []).reduce((total, flow) => {
    const allowed = String(flow?.decision || '').toLowerCase() === 'allow'
      || allowActions.has(String(flow?.action || '').toLowerCase());
    return allowed && flow?.deploymentEligible !== true ? total + Number(flow?.count || 1) : total;
  }, 0);
  const nonDeployableSessions = Math.max(
    Number(data.stats?.nonDeployableSessions || 0),
    legacyUnprovenSessions,
  );
  const scopes = Array.isArray(data.scopes) ? data.scopes : [];
  const multipleScopes = scopes.length > 1;
  const vdomEvidenceMissing = Boolean(
    fortiConfig?.hasVdom
    && fortiConfig?.selectedVdom
    && scopes.some(scope => !String(scope?.vdom || '').trim())
  );
  const hasExcludedTraffic = unsupportedIpv6 > 0
    || invalidFlowRecords > 0
    || archiveEntryErrors > 0
    || unknownActionSessions > 0
    || failedConnectionSessions > 0
    || nonDeployableSessions > 0;
  const blockedReasons = [];
  if (unsupportedIpv6 > 0) blockedReasons.push('ipv6_unsupported');
  if (invalidFlowRecords > 0) blockedReasons.push('invalid_flow_records');
  if (archiveEntryErrors > 0) blockedReasons.push('partial_archive');
  if (unknownActionSessions > 0) blockedReasons.push('unknown_actions');
  if (nonDeployableSessions > 0) blockedReasons.push('unproven_forward_flows');
  if (multipleScopes) blockedReasons.push('multiple_devices_or_vdoms');
  if (vdomEvidenceMissing) blockedReasons.push('vdom_evidence_missing');
  return {
    unsupportedIpv6,
    invalidFlowRecords,
    archiveEntryErrors,
    unknownActionSessions,
    failedConnectionSessions,
    nonDeployableSessions,
    evidenceIssueSessions: data.stats?.evidenceIssueSessions || {},
    multipleScopes,
    scopeCount: scopes.length,
    vdomEvidenceMissing,
    hasExcludedTraffic,
    blockedReasons,
    // Un échec de connexion connu n'est pas une preuve de flux autorisé et reste
    // simplement exclu. En revanche, toute donnée impossible à interpréter avec
    // certitude bloque le CLI final.
    blocked: blockedReasons.length > 0,
  };
}

function isAnalysisOnly(opts) {
  return opts?.analysisOnly === true;
}

module.exports = {
  getCaptureDeploymentBlockers,
  isAnalysisOnly,
};

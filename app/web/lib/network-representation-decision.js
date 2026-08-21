'use strict';

const crypto = require('node:crypto');

const { evaluatePolicies } = require('./policy-engine-v2');
const { analyzePolicies, preflightValidation } = require('./forticonfig');
const {
  NETWORK_RESOLVER_VERSION,
  resolveNetworkRepresentations,
} = require('./network-representation-resolver');

const NETWORK_USER_DECISION_SCHEMA_VERSION = 1;

class NetworkDecisionError extends Error {
  constructor(code, message, statusCode = 422, details = null) {
    super(message);
    this.name = 'NetworkDecisionError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function stableId(prefix, value) {
  return `${prefix}-${crypto.createHash('sha256').update(canonicalJson(value)).digest('hex').slice(0, 16)}`;
}

function sortedUnique(values) {
  return [...new Set((values || []).map(value => String(value)).filter(Boolean))].sort();
}

function validateNetworkUserDecision(decision, context = {}) {
  const reasons = [];
  if (!decision || decision.schemaVersion !== NETWORK_USER_DECISION_SCHEMA_VERSION) reasons.push('SCHEMA_VERSION_MISMATCH');
  if (decision?.resolverVersion !== NETWORK_RESOLVER_VERSION) reasons.push('RESOLVER_VERSION_MISMATCH');
  if (!['accepted', 'invalidated'].includes(decision?.status)) reasons.push('INVALID_STATUS');
  if (decision?.status === 'invalidated') reasons.push('DECISION_ALREADY_INVALIDATED');
  const { resolution, candidate, policy } = context;
  if (context.profile && decision?.profile !== context.profile) reasons.push('PROFILE_MISMATCH');
  if (resolution) {
    if (decision.resolverInputHash !== resolution.resolverInputHash) reasons.push('RESOLVER_INPUT_HASH_MISMATCH');
    if (decision.configFingerprint !== resolution.trace?.configFingerprint) reasons.push('CONFIG_FINGERPRINT_MISMATCH');
    if (decision.trafficScopeKey !== resolution.trace?.trafficScopeKey) reasons.push('TRAFFIC_SCOPE_MISMATCH');
  }
  if (candidate && decision.candidateId !== candidate.candidateId) reasons.push('CANDIDATE_MISMATCH');
  if (policy && decision.policyFingerprint !== resolution?.policyFingerprint) reasons.push('POLICY_FINGERPRINT_MISMATCH');
  return { valid: reasons.length === 0, reasons };
}

function createNetworkUserDecision({ resolution, candidate, policy, profile, now }) {
  if (!resolution || !candidate || !policy) throw new Error('Contexte UserDecision incomplet');
  const decidedAt = new Date(now || Date.now()).toISOString();
  const identity = {
    resolverInputHash: resolution.resolverInputHash,
    policyFingerprint: resolution.policyFingerprint,
    side: resolution.side,
    candidateId: candidate.candidateId,
    profile: String(profile || ''),
  };
  const decision = {
    schemaVersion: NETWORK_USER_DECISION_SCHEMA_VERSION,
    decisionId: stableId('NUD', identity),
    resolverVersion: NETWORK_RESOLVER_VERSION,
    profile: String(profile || ''),
    policyId: String(policy.id || ''),
    policyFingerprint: resolution.policyFingerprint,
    side: resolution.side,
    candidateId: candidate.candidateId,
    resolverInputHash: resolution.resolverInputHash,
    configFingerprint: resolution.trace.configFingerprint,
    trafficScopeKey: resolution.trace.trafficScopeKey,
    action: 'select-candidate',
    status: 'accepted',
    expectedMetrics: structuredClone(candidate.previewMetrics),
    decidedAt,
  };
  const validation = validateNetworkUserDecision(decision, { resolution, candidate, policy, profile });
  if (!validation.valid) throw new Error(`UserDecision invalide : ${validation.reasons.join(', ')}`);
  return decision;
}

function networkDecisionKey(policyId, side) {
  if (!['source', 'destination'].includes(side)) throw new Error(`Côté de décision invalide : ${side}`);
  return `${String(policyId || '')}||${side}`;
}

function revalidateNetworkUserDecision({ decision, engineResult, fortiConfig, now }) {
  const reasons = [];
  const policy = engineResult?.policies?.find(item => String(item.id) === String(decision?.policyId || ''));
  if (!policy) reasons.push('POLICY_NOT_FOUND');
  let resolution = null;
  let candidate = null;
  if (policy && ['source', 'destination'].includes(decision?.side)) {
    resolution = resolveNetworkRepresentations(policy, fortiConfig || {}, { side: decision.side });
    candidate = resolution.candidates.find(item => item.candidateId === decision.candidateId) || null;
    if (!candidate) reasons.push('CANDIDATE_NOT_FOUND');
    const validation = validateNetworkUserDecision(decision, {
      resolution, candidate, policy, profile: engineResult?.profile,
    });
    reasons.push(...validation.reasons);
  } else if (!['source', 'destination'].includes(decision?.side)) {
    reasons.push('INVALID_SIDE');
  }
  const uniqueReasons = sortedUnique([...(decision?.invalidationReasons || []), ...reasons]);
  if (uniqueReasons.length === 0) {
    return { valid: true, decision: structuredClone(decision), reasons: [], resolution };
  }
  return {
    valid: false,
    decision: {
      ...structuredClone(decision),
      status: 'invalidated',
      invalidatedAt: new Date(now || Date.now()).toISOString(),
      invalidationReasons: uniqueReasons,
    },
    reasons: uniqueReasons,
    resolution,
  };
}

function applyExactObject(candidate, copy, side) {
  const match = candidate.existingObjectMatch;
  if (match.ambiguous || match.objectNames.length !== 1) {
    throw new NetworkDecisionError(
      'AMBIGUOUS_CANDIDATE',
      'Le candidat objet exact est ambigu et nécessite un choix d’objet explicite.',
      409,
    );
  }
  const objectName = match.objectNames[0];
  if (side === 'source') {
    copy.allowedSources = [...candidate.representedIps];
    copy._srcAddrName = objectName;
    copy.srcAddrName = objectName;
    copy._use32Src = false;
    if (match.cidr) {
      copy.srcSubnet = match.cidr;
      copy.srcSubnets = [match.cidr];
      copy._srcCidrOverride = match.cidr;
      copy._srcMode = 'subnet';
    }
  } else {
    copy.allowedDestinations = [...candidate.representedIps];
    copy._dstAddrName = objectName;
    copy.dstAddrName = objectName;
    copy._use32Dst = false;
    if (match.cidr) {
      copy.dstTarget = match.cidr;
      copy.dstTargets = [match.cidr];
      copy._dstCidrOverride = match.cidr;
      copy._dstMode = 'subnet';
    }
  }
}

function applyHostList(candidate, copy, side) {
  if (side === 'source') {
    copy.allowedSources = [...candidate.representedIps];
    copy._use32Src = true;
    copy._srcMode = 'hosts';
  } else {
    copy.allowedDestinations = [...candidate.representedIps];
    copy._use32Dst = true;
    copy._dstMode = 'hosts';
  }
}

function applyExactGroup(candidate, copy, side) {
  const group = candidate.exactGroupCandidate;
  if (group.ambiguous || !group.groupName) {
    throw new NetworkDecisionError(
      'AMBIGUOUS_CANDIDATE',
      'Le candidat groupe exact est ambigu et nécessite un choix explicite.',
      409,
    );
  }
  if (side === 'source') {
    copy.allowedSources = [...candidate.representedIps];
    copy._srcAddrName = group.groupName;
    copy.srcAddrName = group.groupName;
    copy._srcAddrGrpFound = true;
    copy._useSrcGroup = true;
    copy._use32Src = false;
    copy._srcMode = 'hosts';
  } else {
    copy.allowedDestinations = [...candidate.representedIps];
    copy._dstAddrName = group.groupName;
    copy.dstAddrName = group.groupName;
    copy._dstAddrGrpFound = true;
    copy._useDstGroup = true;
    copy._use32Dst = false;
    copy._dstMode = 'hosts';
  }
}

function applyCidrSuggestion(candidate, copy, side) {
  const cidr = candidate.cidrCandidate.cidr;
  const objectNames = candidate.cidrCandidate.existingMatches
    .flatMap(match => match.objectNames || []);
  if (side === 'source') {
    copy.allowedSources = [...candidate.representedIps];
    copy.srcSubnet = cidr;
    copy.srcSubnets = [cidr];
    copy._srcCidrOverride = cidr;
    copy._use32Src = false;
    copy._srcMode = 'subnet';
    if (objectNames.length === 1) {
      copy._srcAddrName = objectNames[0];
      copy.srcAddrName = objectNames[0];
    }
  } else {
    copy.allowedDestinations = [...candidate.representedIps];
    copy.dstTarget = cidr;
    copy.dstTargets = [cidr];
    copy._dstCidrOverride = cidr;
    copy._use32Dst = false;
    copy._dstMode = 'subnet';
    if (objectNames.length === 1) {
      copy._dstAddrName = objectNames[0];
      copy.dstAddrName = objectNames[0];
    }
  }
}

function applyNewExactGroup(candidate, copy, side) {
  const reused = new Map((candidate.exactGroupCandidate.reusedHostObjects || [])
    .map(item => [item.ip, item.objectNames || []]));
  const subnets = candidate.representedIps.map(ip => {
    const names = reused.get(ip) || [];
    return {
      subnet: `${ip}/32`,
      hosts: [ip],
      useSubnet: false,
      addrFound: names.length === 1,
      addrName: names.length === 1 ? names[0] : '',
    };
  });
  if (side === 'source') {
    copy.allowedSources = [...candidate.representedIps];
    copy._multiSrcSubnets = subnets;
    copy._useSrcGroup = true;
    copy._use32Src = false;
    copy._srcMode = 'hosts';
  } else {
    copy.allowedDestinations = [...candidate.representedIps];
    copy._multiDstSubnets = subnets;
    copy._isMultiDst = true;
    copy._useDstGroup = true;
    copy._use32Dst = false;
    copy._dstMode = 'hosts';
  }
}

function applyCandidateToPolicy(policy, candidate, side, decision) {
  const copy = structuredClone(policy);
  if (candidate.kind === 'existing-object') applyExactObject(candidate, copy, side);
  else if (candidate.kind === 'existing-group') applyExactGroup(candidate, copy, side);
  else if (candidate.kind === 'new-exact-group') applyNewExactGroup(candidate, copy, side);
  else if (candidate.kind === 'cidr-suggestion') applyCidrSuggestion(candidate, copy, side);
  else if (candidate.kind === 'host-list') applyHostList(candidate, copy, side);
  else throw new NetworkDecisionError(
    'CANDIDATE_KIND_NOT_IMPLEMENTED',
    `Application du candidat ${candidate.kind} non implémentée`,
  );
  copy._networkRepresentationDecision = {
    decisionId: decision.decisionId,
    candidateId: candidate.candidateId,
    resolverInputHash: decision.resolverInputHash,
    side,
  };
  return copy;
}

function assertSafeMetrics(metrics) {
  if (metrics.missingRequiredTuples !== 0 || metrics.unexpectedAllowedTuples !== 0) {
    throw new NetworkDecisionError(
      'UNSAFE_NETWORK_REPRESENTATION',
      'La représentation réseau modifie les tuples autorisés.',
      422,
      { metrics },
    );
  }
}

function applyNetworkRepresentationDecision({
  engineResult,
  fortiConfig,
  observedFlows,
  policyId,
  side,
  candidateId,
  resolverInputHash,
  now,
}) {
  if (!engineResult || !Array.isArray(engineResult.policies) || !Array.isArray(engineResult.atoms)) {
    throw new NetworkDecisionError('INVALID_ENGINE_RESULT', 'Résultat Policy Engine V2 invalide');
  }
  if (!['source', 'destination'].includes(side)) {
    throw new NetworkDecisionError('INVALID_SIDE', `Côté de décision invalide : ${side}`, 400);
  }
  const policy = engineResult.policies.find(item => String(item.id) === String(policyId || ''));
  if (!policy) throw new NetworkDecisionError('POLICY_NOT_FOUND', `Policy V2 introuvable : ${policyId}`, 404);
  if (policy._policyEngineV2?.safeExact !== true) {
    throw new NetworkDecisionError('POLICY_NOT_EXACT', 'Une policy V2 exacte est requise', 409);
  }
  const resolution = resolveNetworkRepresentations(policy, fortiConfig || {}, { side });
  if (resolution.resolverInputHash !== resolverInputHash) {
    throw new NetworkDecisionError(
      'STALE_DECISION_CONTEXT',
      'Le contexte resolver a changé ; les candidats doivent être recalculés.',
      409,
      {
        expectedResolverInputHash: resolution.resolverInputHash,
        providedResolverInputHash: resolverInputHash,
      },
    );
  }
  const candidate = resolution.candidates.find(item => item.candidateId === candidateId);
  if (!candidate) {
    throw new NetworkDecisionError('CANDIDATE_NOT_FOUND', `Candidat introuvable : ${candidateId}`, 404);
  }
  if (candidate.eligibility === 'blocked') {
    throw new NetworkDecisionError('CANDIDATE_BLOCKED', 'Le candidat est bloqué par le resolver', 409);
  }
  const decision = createNetworkUserDecision({
    resolution, candidate, policy, profile: engineResult.profile, now,
  });
  const appliedPolicies = structuredClone(engineResult.policies);
  const selectedIndex = appliedPolicies.findIndex(item => String(item.id) === String(policy.id));
  const appliedPolicy = applyCandidateToPolicy(
    appliedPolicies[selectedIndex], candidate, side, decision,
  );
  appliedPolicies[selectedIndex] = appliedPolicy;
  const metrics = evaluatePolicies(engineResult.atoms, appliedPolicies);
  metrics.blockedRequiredTuples = Number(engineResult.metrics?.blockedRequiredTuples || 0);
  metrics.deployableRequiredTuples = metrics.observedRequiredTuples - metrics.blockedRequiredTuples;
  assertSafeMetrics(metrics);
  const analyzedPolicies = analyzePolicies(appliedPolicies, fortiConfig || {}, null);
  const analyzedPolicy = analyzedPolicies.find(item => String(item.id) === String(policy.id));
  const preflight = preflightValidation(
    analyzedPolicies,
    fortiConfig || {},
    Array.isArray(observedFlows) ? observedFlows : [],
    engineResult.atoms,
  );
  return {
    decision,
    appliedPolicy,
    analyzedPolicy,
    metrics,
    preflight,
    generationEligible: preflight.ok && metrics.missingRequiredTuples === 0
      && metrics.unexpectedAllowedTuples === 0,
  };
}

module.exports = {
  NETWORK_USER_DECISION_SCHEMA_VERSION,
  NetworkDecisionError,
  applyNetworkRepresentationDecision,
  createNetworkUserDecision,
  networkDecisionKey,
  revalidateNetworkUserDecision,
  validateNetworkUserDecision,
};

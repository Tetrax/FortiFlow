'use strict';

const {
  NETWORK_REPRESENTATION_SCHEMA_VERSION,
  NETWORK_RESOLVER_VERSION,
  resolveNetworkRepresentations,
  validateResolutionResult,
} = require('./network-representation-resolver');

function clone(value) {
  return value == null ? value : structuredClone(value);
}

function projectCandidate(candidate) {
  return {
    candidateId: candidate.candidateId,
    kind: candidate.kind,
    rank: candidate.rank,
    side: candidate.side,
    representation: clone(candidate.representation),
    origin: clone(candidate.origin),
    objects: clone(candidate.objects),
    representedCidrs: [...candidate.representedCidrs],
    observedIpCount: candidate.observedIpCount,
    representedIpCount: candidate.representedIpCount,
    additionalIpCount: candidate.additionalIpCount,
    missingIpCount: candidate.missingIpCount,
    affectedDestinationCount: candidate.affectedDestinationCount,
    affectedSourceCount: candidate.affectedSourceCount,
    affectedServiceKeys: [...candidate.affectedServiceKeys],
    previewMetrics: clone(candidate.previewMetrics),
    reasonCodes: [...candidate.reasonCodes],
    safetyState: {
      eligibility: candidate.eligibility,
      autoApplicable: candidate.autoApplicable,
    },
    explanation: candidate.explanation,
    ...(candidate.existingObjectMatch
      ? { existingObjectMatch: clone(candidate.existingObjectMatch) } : {}),
    ...(candidate.exactGroupCandidate
      ? { exactGroupCandidate: clone(candidate.exactGroupCandidate) } : {}),
    ...(candidate.cidrCandidate
      ? { cidrCandidate: clone(candidate.cidrCandidate) } : {}),
  };
}

function projectResolution(result) {
  if (!validateResolutionResult(result)) throw new Error('Résultat resolver invalide');
  return {
    resolverInputHash: result.resolverInputHash,
    resolutionId: result.resolutionId,
    currentCandidateId: result.currentRepresentation.candidateId,
    recommendedCandidateId: result.recommendedCandidateId,
    status: result.status,
    blockers: clone(result.blockers),
    candidates: result.candidates.map(projectCandidate),
  };
}

function buildPolicyRepresentationCandidates(engineResult, fortiConfig, policyId, options = {}) {
  if (!engineResult || !Array.isArray(engineResult.policies)) {
    throw new Error('Résultat Policy Engine V2 invalide');
  }
  const requestedId = String(policyId || '');
  if (!requestedId) throw new Error('policy_id requis');
  const policy = engineResult.policies.find(item => String(item.id) === requestedId);
  if (!policy) throw new Error(`Policy V2 introuvable : ${requestedId}`);
  if (policy._policyEngineV2?.safeExact !== true) {
    throw new Error('Une policy V2 exacte est requise pour calculer les représentations réseau');
  }
  const source = resolveNetworkRepresentations(policy, fortiConfig || {}, {
    side: 'source',
    maxCandidateAddresses: options.maxCandidateAddresses,
    maxCidrCandidates: options.maxCidrCandidates,
  });
  const destination = resolveNetworkRepresentations(policy, fortiConfig || {}, {
    side: 'destination',
    maxCandidateAddresses: options.maxCandidateAddresses,
    maxCidrCandidates: options.maxCidrCandidates,
  });
  if (source.policyFingerprint !== destination.policyFingerprint) {
    throw new Error('Resolver source/destination incohérent');
  }
  return {
    schemaVersion: NETWORK_REPRESENTATION_SCHEMA_VERSION,
    resolverVersion: NETWORK_RESOLVER_VERSION,
    policyId: requestedId,
    policyFingerprint: source.policyFingerprint,
    trafficScopeKey: String(policy._policyEngineV2?.trafficScopeKey || engineResult.trafficScope?.key || ''),
    source: projectResolution(source),
    destination: projectResolution(destination),
  };
}

module.exports = {
  buildPolicyRepresentationCandidates,
};

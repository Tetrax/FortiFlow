'use strict';

const { trafficScopeKey } = require('./traffic-scope');
const { validatePolicyAddressSelections } = require('./forticonfig');

const POLICY_ENGINE_PROFILES = new Set(['recommended', 'strict', 'synthetic', 'expert']);
const SAFE_OPERATION_FIELDS = [
  'action', '_action',
  'log', '_log',
  'nat', '_nat',
  'policyName', '_policyName',
  'securityProfiles', '_secProfiles',
  'disabled', '_disabled',
];

function clone(value) {
  if (typeof structuredClone === 'function') return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value || {}, key);
}

function isV2Submission(policy) {
  return hasOwn(policy, '_policyEngineV2')
    || hasOwn(policy, 'profile')
    || /^P-/.test(String(policy?.id || ''));
}

function safeSelection(selection) {
  if (!isObject(selection)) return selection;
  const result = {};
  for (const key of ['mode', 'type', 'objectName', 'name', 'cidr', 'confirmed']) {
    if (hasOwn(selection, key)) result[key] = selection[key];
  }
  for (const key of ['ips', 'hosts', 'observedIps']) {
    if (hasOwn(selection, key)) result[key] = Array.isArray(selection[key]) ? [...selection[key]] : selection[key];
  }
  return result;
}

function safeAddressSelections(policy) {
  const submitted = hasOwn(policy, 'addressSelections')
    ? policy.addressSelections
    : policy._addressSelections;
  if (submitted === undefined) return { present: false, value: undefined, validShape: true };
  if (!isObject(submitted)) return { present: true, value: submitted, validShape: false };
  const value = {};
  const source = submitted.source ?? submitted.src;
  const destination = submitted.destination ?? submitted.dst;
  if (source !== undefined) value.source = safeSelection(source);
  if (destination !== undefined) value.destination = safeSelection(destination);
  return { present: true, value, validShape: true };
}

function issue(index, message) {
  return {
    level: 'error',
    code: 'POLICY_ENGINE_PROVENANCE_INVALID',
    msg: `Policy #${index + 1}: ${message}`,
  };
}

function bindPolicyEngineV2Selections(submittedPolicies, options = {}) {
  const policies = Array.isArray(submittedPolicies) ? submittedPolicies : [];
  const fortiConfig = options.fortiConfig || {};
  const getPolicyEngineResult = options.getPolicyEngineResult;
  const issues = [];
  const boundPolicies = [];
  const resultCache = new Map();

  if (typeof getPolicyEngineResult !== 'function') {
    return {
      ok: false,
      policies: [],
      issues: [issue(0, 'résolveur Policy Engine V2 serveur manquant')],
    };
  }

  for (let index = 0; index < policies.length; index++) {
    const submitted = policies[index] || {};
    if (!isV2Submission(submitted)) {
      boundPolicies.push(submitted);
      continue;
    }

    const provenance = submitted._policyEngineV2;
    if (!isObject(provenance)) {
      issues.push(issue(index, 'provenance Policy Engine V2 absente'));
      continue;
    }
    const profile = String(provenance.profile || '').trim();
    const id = String(provenance.id || submitted.id || '').trim();
    const scope = provenance.trafficScope;
    const scopeKey = String(provenance.trafficScopeKey || '').trim();
    if (!POLICY_ENGINE_PROFILES.has(profile) || !id || !isObject(scope) || !scopeKey) {
      issues.push(issue(index, 'profil, identifiant stable ou Traffic Scope manquant'));
      continue;
    }

    let normalizedScopeKey;
    try {
      normalizedScopeKey = trafficScopeKey(scope);
    } catch (error) {
      issues.push(issue(index, `Traffic Scope invalide : ${error.message}`));
      continue;
    }
    if (normalizedScopeKey !== scopeKey) {
      issues.push(issue(index, 'Traffic Scope altéré'));
      continue;
    }

    const cacheKey = `${profile}||${scopeKey}`;
    let serverResult = resultCache.get(cacheKey);
    if (!serverResult) {
      try {
        serverResult = getPolicyEngineResult(profile, scope);
      } catch (error) {
        issues.push(issue(index, `résultat serveur indisponible : ${error.message}`));
        continue;
      }
      resultCache.set(cacheKey, serverResult);
    }
    const serverPolicy = serverResult?.policies?.find(policy => String(policy.id) === id);
    if (!serverPolicy) {
      issues.push(issue(index, `identifiant Policy Engine V2 inconnu : ${id}`));
      continue;
    }

    const effective = clone(serverPolicy);
    effective._serverPolicyBinding = true;
    for (const field of SAFE_OPERATION_FIELDS) {
      if (hasOwn(submitted, field)) effective[field] = clone(submitted[field]);
    }

    const selections = safeAddressSelections(submitted);
    if (!selections.validShape) {
      issues.push(issue(index, 'sélections d’adresse invalides'));
      continue;
    }
    if (selections.present) {
      effective.addressSelections = selections.value;
      const validation = validatePolicyAddressSelections([effective], fortiConfig);
      if (!validation.ok) {
        issues.push(...validation.issues.map(item => ({
          ...item,
          code: 'ADDRESS_SELECTION_INVALID',
        })));
        continue;
      }
    }
    boundPolicies.push(effective);
  }

  return {
    ok: issues.length === 0,
    policies: boundPolicies,
    issues,
  };
}

module.exports = {
  bindPolicyEngineV2Selections,
  POLICY_ENGINE_PROFILES,
};

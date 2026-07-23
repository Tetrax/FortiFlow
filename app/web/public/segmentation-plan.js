'use strict';

(function initSegmentationPlan(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.FortiFlowSegmentation = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function segmentationPlanFactory() {
  const VALID = {
    source: new Set(['network', 'host']),
    destination: new Set(['network', 'host']),
    services: new Set(['grouped', 'separate']),
  };

  function normalizePlan(plan) {
    const input = plan || {};
    return {
      source: VALID.source.has(input.source) ? input.source : 'network',
      destination: VALID.destination.has(input.destination) ? input.destination : 'network',
      services: VALID.services.has(input.services) ? input.services : 'grouped',
    };
  }

  function inferPreset(plan) {
    const p = normalizePlan(plan);
    if (p.source === 'network' && p.destination === 'network' && p.services === 'grouped') return 'wide';
    if (p.source === 'network' && p.destination === 'host' && p.services === 'grouped') return 'targeted';
    if (p.source === 'host' && p.destination === 'host' && p.services === 'separate') return 'strict';
    return 'custom';
  }

  function unique(values) {
    return [...new Set((values || []).filter(Boolean))];
  }

  function serviceKey(service) {
    if (!service) return '';
    return String(service.label || service.name || ((service.proto || '') + '/' + (service.port || ''))).toUpperCase();
  }

  function serviceObserved(pairServices, service) {
    if (!pairServices || !service) return false;
    const wanted = serviceKey(service);
    return pairServices.some(value => String(value).toUpperCase() === wanted);
  }

  function buildPoliciesByPlan(analyzedPolicies, plan, options) {
    const normalized = normalizePlan(plan);
    const opts = options || {};
    const hostPairServices = opts.hostPairServices || null;
    const getServicesForPair = typeof opts.getServicesForPair === 'function'
      ? opts.getServicesForPair
      : function fallbackServices(_src, _dst, policy) { return (policy.analysis && policy.analysis.services) || []; };
    const result = [];

    for (const policy of (analyzedPolicies || [])) {
      const srcHosts = unique(policy.srcHosts);
      const dstHosts = unique(policy.dstHosts);
      const isWan = !!(policy._isWan || policy.dstType === 'public');
      const sourceMode = normalized.source;
      const destinationMode = isWan ? 'host' : normalized.destination;
      const srcList = sourceMode === 'host' && srcHosts.length ? srcHosts : [null];
      const dstList = destinationMode === 'host' && dstHosts.length ? dstHosts : [null];
      const outputs = [];

      for (const srcHost of srcList) {
        for (const dstHost of dstList) {
          if (hostPairServices && srcHost && dstHost && !hostPairServices[srcHost + '|' + dstHost]) continue;

          let scopedSrc = srcHost ? [srcHost] : srcHosts.slice();
          let scopedDst = dstHost ? [dstHost] : dstHosts.slice();
          const serviceMap = new Map();

          if (scopedSrc.length && scopedDst.length) {
            const validSrc = new Set();
            const validDst = new Set();
            for (const src of scopedSrc) {
              for (const dst of scopedDst) {
                if (hostPairServices && !hostPairServices[src + '|' + dst]) continue;
                const services = getServicesForPair(src, dst, policy) || [];
                if (services.length) {
                  validSrc.add(src);
                  validDst.add(dst);
                  for (const service of services) serviceMap.set(serviceKey(service), service);
                }
              }
            }
            if (hostPairServices) {
              if (validSrc.size) scopedSrc = scopedSrc.filter(value => validSrc.has(value));
              if (validDst.size) scopedDst = scopedDst.filter(value => validDst.has(value));
            }
          }

          if (!serviceMap.size) {
            for (const service of ((policy.analysis && policy.analysis.services) || [])) {
              serviceMap.set(serviceKey(service), service);
            }
          }

          const services = [...serviceMap.values()];
          const serviceGroups = normalized.services === 'separate' && services.length
            ? services.map(service => [service])
            : [services];

          for (const serviceGroup of serviceGroups) {
            let serviceSrc = scopedSrc;
            let serviceDst = scopedDst;
            const selectedService = serviceGroup.length === 1 ? serviceGroup[0] : null;

            if (normalized.services === 'separate' && selectedService && hostPairServices && scopedSrc.length && scopedDst.length) {
              const filteredSrc = scopedSrc.filter(src =>
                scopedDst.some(dst => serviceObserved(hostPairServices[src + '|' + dst], selectedService))
              );
              const filteredDst = scopedDst.filter(dst =>
                scopedSrc.some(src => serviceObserved(hostPairServices[src + '|' + dst], selectedService))
              );
              if (filteredSrc.length) serviceSrc = filteredSrc;
              if (filteredDst.length) serviceDst = filteredDst;
            }

            const labels = serviceGroup.map(service => service.label || service.name).filter(Boolean);
            const noRcvdSrcSet = new Set(policy.noRcvdSrcHosts || []);
            outputs.push({
              ...policy,
              srcSubnet: srcHost ? srcHost + '/32' : policy.srcSubnet,
              dstTarget: dstHost ? dstHost + '/32' : policy.dstTarget,
              srcHosts: serviceSrc,
              dstHosts: serviceDst,
              _use32Src: sourceMode === 'host',
              _use32Dst: destinationMode === 'host',
              _srcMode: sourceMode === 'host' ? 'hosts' : 'subnet',
              _dstMode: destinationMode === 'host' ? 'hosts' : 'subnet',
              serviceDesc: labels.length ? labels.join(', ') : policy.serviceDesc,
              analysis: { ...(policy.analysis || {}), services: serviceGroup },
              noRcvdFlows: srcHost ? (noRcvdSrcSet.has(srcHost) ? 1 : 0) : (policy.noRcvdFlows || 0),
              _segmentationPlan: normalized,
            });
          }
        }
      }

      if (!outputs.length) {
        outputs.push({
          ...policy,
          _use32Src: sourceMode === 'host',
          _use32Dst: destinationMode === 'host',
          _srcMode: sourceMode === 'host' ? 'hosts' : 'subnet',
          _dstMode: destinationMode === 'host' ? 'hosts' : 'subnet',
          _segmentationPlan: normalized,
          _hpsUnverified: true,
        });
      }

      const divisor = outputs.length || 1;
      for (const output of outputs) {
        for (const field of ['sessions', 'bytes', 'sentBytes', 'rcvdBytes']) {
          if (Number.isFinite(policy[field])) {
            output[field] = Math.max(field === 'sessions' ? 1 : 0, Math.round(policy[field] / divisor));
          }
        }
        result.push(output);
      }
    }

    return result;
  }

  return { normalizePlan, inferPreset, buildPoliciesByPlan };
});

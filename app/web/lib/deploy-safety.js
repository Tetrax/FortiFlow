'use strict';

function getCaptureDeploymentBlockers(sessionData) {
  const data = sessionData || {};
  const unsupportedIpv6 = Number(data.meta?.skipReasons?.ipv6 || 0);
  const unknownActionSessions = Number(data.stats?.unknownSessions || 0);
  const hasExcludedTraffic = unsupportedIpv6 > 0 || unknownActionSessions > 0;
  return {
    unsupportedIpv6,
    unknownActionSessions,
    hasExcludedTraffic,
    // Ces flux sont exclus des suggestions. Ils peuvent rendre la matrice
    // sous-permissive, mais ne peuvent pas élargir une policy sélectionnée.
    blocked: false,
  };
}

function isAnalysisOnly(opts) {
  return opts?.analysisOnly === true;
}

module.exports = {
  getCaptureDeploymentBlockers,
  isAnalysisOnly,
};

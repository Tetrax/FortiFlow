'use strict';

function getCaptureDeploymentBlockers(sessionData) {
  const data = sessionData || {};
  const unsupportedIpv6 = Number(data.meta?.skipReasons?.ipv6 || 0);
  const unknownActionSessions = Number(data.stats?.unknownSessions || 0);
  return {
    unsupportedIpv6,
    unknownActionSessions,
    blocked: unsupportedIpv6 > 0 || unknownActionSessions > 0,
  };
}

function isAnalysisOnly(opts) {
  return opts?.analysisOnly === true;
}

function shouldBlockCaptureGeneration(sessionData, opts) {
  return !isAnalysisOnly(opts) && getCaptureDeploymentBlockers(sessionData).blocked;
}

module.exports = {
  getCaptureDeploymentBlockers,
  isAnalysisOnly,
  shouldBlockCaptureGeneration,
};

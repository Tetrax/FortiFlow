'use strict';

const { parentPort, workerData } = require('node:worker_threads');
const { parseFile } = require('./parser');
const { buildAnalysis } = require('./analyzer');

function emptyFlowError({ lineCount, skipReasons }) {
  const reasons = [];
  if (skipReasons?.invalidFlow) reasons.push(`${skipReasons.invalidFlow} ligne(s) sans IP source/destination exploitable`);
  if (skipReasons?.nonTraffic) reasons.push(`${skipReasons.nonTraffic} ligne(s) hors trafic`);
  if (skipReasons?.ipv6) reasons.push(`${skipReasons.ipv6} flux IPv6 non pris en charge`);
  const detail = reasons.length ? ` Détail : ${reasons.join(', ')}.` : '';
  return (
    `Fichier lu (${lineCount.toLocaleString('fr-FR')} lignes), mais aucun flux exploitable n’a été trouvé.${detail} ` +
    'Vérifiez le séparateur CSV et la présence des colonnes srcip, dstip, action, service/dstport et proto.'
  );
}

async function run() {
  const { filePath, filename } = workerData;

  const parsed = await parseFile(filePath, info => {
    parentPort.postMessage({ type: 'progress', data: { phase: 'parsing', ...info } });
  });

  if (parsed.flowMap.size === 0) {
    throw new Error(emptyFlowError(parsed));
  }

  parentPort.postMessage({
    type: 'progress',
    data: {
      phase: 'analysis',
      lines: parsed.lineCount,
      pct: 99,
      linesPerSec: 0,
      eta: 0,
    },
  });

  const analysis = buildAnalysis(parsed.flowMap);
  analysis.meta = {
    lineCount: parsed.lineCount,
    skipped: parsed.skipped,
    skipReasons: parsed.skipReasons,
    uniqueFlows: parsed.flowMap.size,
    filename,
  };

  parentPort.postMessage({ type: 'result', analysis });
}

run()
  .catch(error => {
    parentPort.postMessage({
      type: 'error',
      error: {
        message: error?.message || String(error),
        code: error?.code || 'ANALYSIS_FAILED',
      },
    });
  })
  .finally(() => parentPort.close());

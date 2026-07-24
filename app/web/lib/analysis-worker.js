'use strict';

const fs = require('node:fs/promises');
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

function possibleFazDownloadLimit(lineCount) {
  const knownLimits = new Set([100000, 500000, 1000000, 2000000, 5000000]);
  return knownLimits.has(Number(lineCount)) ? Number(lineCount) : null;
}

async function run() {
  const { filePath, filename, cache } = workerData;

  parentPort.postMessage({
    type: 'progress',
    data: { phase: 'parsing', lines: 0, pct: 0, linesPerSec: 0, eta: null },
  });

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
    dedupe: parsed.dedupe || {
      duplicateRecords: 0,
      sessionRecords: 0,
      trackedSessions: 0,
      saturated: false,
    },
    possibleFazDownloadLimit: possibleFazDownloadLimit(parsed.lineCount),
    uniqueFlows: parsed.flowMap.size,
    filename,
  };

  let cacheSaved = false;
  if (cache?.path && cache?.id) {
    const tmpPath = `${cache.path}.${process.pid}.${Date.now()}.tmp`;
    try {
      parentPort.postMessage({
        type: 'progress',
        data: { phase: 'persistence', lines: parsed.lineCount, pct: 99, linesPerSec: 0, eta: 0 },
      });
      const payload = JSON.stringify({
        id: cache.id,
        createdAt: cache.createdAt,
        lastAccess: Date.now(),
        status: 'ready',
        data: analysis,
        fortiConfig: null,
      });
      await fs.writeFile(tmpPath, payload, 'utf8');
      await fs.rename(tmpPath, cache.path);
      cacheSaved = true;
    } catch {
      await fs.unlink(tmpPath).catch(() => {});
    }
  }

  parentPort.postMessage({ type: 'result', analysis, cacheSaved });
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

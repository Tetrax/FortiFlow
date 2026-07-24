'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { AnalysisPool } = require('../lib/analysis-pool');

test('le parsing lourd est isolé dans un worker sans modifier le résultat du moteur', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'fortiflow-worker-'));
  const filePath = path.join(dir, 'traffic.log');
  const log = [
    'date=2026-07-24 time=10:00:00 type=traffic devname="FGT-A" vd="root" srcip=10.0.0.10 dstip=10.0.1.20 srcport=50000 dstport=443 proto=6 action=accept service=HTTPS srcintf="lan" dstintf="servers" sentbyte=100 rcvdbyte=200',
    'date=2026-07-24 time=10:00:01 type=traffic devname="FGT-A" vd="root" srcip=10.0.0.11 dstip=10.0.1.53 srcport=50001 dstport=53 proto=17 action=accept service=DNS srcintf="lan" dstintf="servers" sentbyte=80 rcvdbyte=120',
  ].join('\n');
  await fs.writeFile(filePath, log, 'utf8');

  const pool = new AnalysisPool({ maxWorkers: 1, maxQueue: 1 });
  t.after(async () => {
    await pool.close();
    await fs.rm(dir, { recursive: true, force: true });
  });

  const phases = [];
  const analysis = await pool.run({
    jobId: 'worker-test',
    filePath,
    filename: 'traffic.log',
    onProgress: progress => phases.push(progress.phase),
  });

  assert.equal(analysis.meta.lineCount, 2);
  assert.equal(analysis.meta.uniqueFlows, 2);
  assert.equal(analysis.stats.acceptSessions, 2);
  assert.equal(analysis.policies.length, 2);
  assert.ok(phases.includes('starting'));
  assert.ok(phases.includes('parsing'));
  assert.ok(phases.includes('analysis'));
  assert.deepEqual(pool.stats(), {
    active: 0,
    queued: 0,
    maxWorkers: 1,
    maxQueue: 1,
  });
});

test('la file d’analyse refuse proprement les nouvelles charges quand elle est saturée', async () => {
  const pool = new AnalysisPool({ maxWorkers: 1, maxQueue: 1 });
  pool.active.set('active', {});
  pool.queue.push({ jobId: 'queued', onProgress() {} });

  assert.equal(pool.canAccept(), false);
  await assert.rejects(
    pool.run({ jobId: 'overflow', filePath: '/tmp/missing.log', filename: 'missing.log' }),
    error => error.code === 'ANALYSIS_QUEUE_FULL',
  );

  pool.active.clear();
  pool.queue.length = 0;
  await pool.close();
});

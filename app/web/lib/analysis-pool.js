'use strict';

const path = require('node:path');
const { Worker } = require('node:worker_threads');

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

class AnalysisPool {
  constructor(options = {}) {
    this.maxWorkers = positiveInt(options.maxWorkers ?? process.env.MAX_ANALYSIS_WORKERS, 1);
    this.maxQueue = positiveInt(options.maxQueue ?? process.env.MAX_ANALYSIS_QUEUE, 3);
    this.workerMemoryMb = positiveInt(options.workerMemoryMb ?? process.env.ANALYSIS_WORKER_MEMORY_MB, 0);
    this.workerFile = options.workerFile || path.join(__dirname, 'analysis-worker.js');
    this.queue = [];
    this.active = new Map();
    this.closed = false;
  }

  canAccept() {
    return !this.closed && (this.active.size + this.queue.length) < (this.maxWorkers + this.maxQueue);
  }

  stats() {
    return {
      active: this.active.size,
      queued: this.queue.length,
      maxWorkers: this.maxWorkers,
      maxQueue: this.maxQueue,
    };
  }

  run({ jobId, filePath, filename, onProgress }) {
    if (!jobId || !filePath) {
      return Promise.reject(Object.assign(new Error('Job d’analyse invalide'), { code: 'INVALID_ANALYSIS_JOB' }));
    }
    if (!this.canAccept()) {
      return Promise.reject(Object.assign(
        new Error('Le moteur d’analyse est occupé. Réessayez après la fin d’un traitement en cours.'),
        { code: 'ANALYSIS_QUEUE_FULL' },
      ));
    }

    return new Promise((resolve, reject) => {
      const job = {
        jobId,
        filePath,
        filename,
        onProgress: typeof onProgress === 'function' ? onProgress : () => {},
        resolve,
        reject,
        worker: null,
        settled: false,
      };
      this.queue.push(job);
      this._notifyQueue();
      this._drain();
    });
  }

  cancel(jobId) {
    const queuedIndex = this.queue.findIndex(job => job.jobId === jobId);
    if (queuedIndex >= 0) {
      const [job] = this.queue.splice(queuedIndex, 1);
      job.settled = true;
      job.reject(Object.assign(new Error('Analyse annulée'), { code: 'ANALYSIS_CANCELLED' }));
      this._notifyQueue();
      return true;
    }

    const activeJob = this.active.get(jobId);
    if (!activeJob) return false;
    this._settle(activeJob, Object.assign(new Error('Analyse annulée'), { code: 'ANALYSIS_CANCELLED' }));
    return true;
  }

  async close() {
    this.closed = true;
    const queued = this.queue.splice(0);
    for (const job of queued) {
      job.settled = true;
      job.reject(Object.assign(new Error('Moteur d’analyse arrêté'), { code: 'ANALYSIS_POOL_CLOSED' }));
    }
    await Promise.all([...this.active.values()].map(job => job.worker?.terminate().catch(() => {})));
    this.active.clear();
  }

  _notifyQueue() {
    this.queue.forEach((job, index) => {
      job.onProgress({
        phase: 'queued',
        queuePosition: index + 1,
        queued: this.queue.length,
        active: this.active.size,
        pct: 0,
        lines: 0,
      });
    });
  }

  _drain() {
    if (this.closed) return;
    while (this.active.size < this.maxWorkers && this.queue.length) {
      const job = this.queue.shift();
      this._start(job);
    }
    this._notifyQueue();
  }

  _start(job) {
    const workerOptions = {
      workerData: { filePath: job.filePath, filename: job.filename },
    };
    if (this.workerMemoryMb >= 256) {
      workerOptions.resourceLimits = { maxOldGenerationSizeMb: this.workerMemoryMb };
    }

    const worker = new Worker(this.workerFile, workerOptions);
    job.worker = worker;
    this.active.set(job.jobId, job);
    job.onProgress({ phase: 'starting', pct: 0, lines: 0 });

    worker.on('message', message => {
      if (job.settled || !message) return;
      if (message.type === 'progress') {
        job.onProgress(message.data || {});
        return;
      }
      if (message.type === 'result') {
        this._settle(job, null, message.analysis);
        return;
      }
      if (message.type === 'error') {
        const error = Object.assign(
          new Error(message.error?.message || 'Échec du moteur d’analyse'),
          { code: message.error?.code || 'ANALYSIS_FAILED' },
        );
        this._settle(job, error);
      }
    });

    worker.once('error', error => this._settle(job, error));
    worker.once('exit', code => {
      if (!job.settled) {
        const message = code === 0
          ? 'Le worker d’analyse s’est arrêté sans résultat'
          : `Le worker d’analyse s’est arrêté avec le code ${code}`;
        this._settle(job, Object.assign(new Error(message), { code: 'ANALYSIS_WORKER_EXIT' }));
      }
    });
  }

  _settle(job, error, result) {
    if (job.settled) return;
    job.settled = true;
    this.active.delete(job.jobId);

    if (job.worker) {
      job.worker.removeAllListeners();
      job.worker.terminate().catch(() => {});
    }

    if (error) job.reject(error);
    else job.resolve(result);

    this._drain();
  }
}

module.exports = { AnalysisPool };

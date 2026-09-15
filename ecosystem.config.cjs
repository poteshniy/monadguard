/**
 * PM2. Two processes on purpose:
 *
 *   monadguard-api    — stateless HTTP, restarts freely
 *   monadguard-worker — owns the anchor queue and spends gas
 *
 * They are split because the worker must be a SINGLE instance. Two workers
 * sweeping the same SQLite queue will build two batches from the same rows,
 * send both, and burn gas anchoring duplicates — and with the same sender
 * nonce, one of them just fails. Never set instances > 1 here, and never run
 * `npm run worker` by hand while PM2 has it up.
 *
 *   pm2 start ecosystem.config.cjs
 *   pm2 logs monadguard-worker
 *   pm2 save && pm2 startup      # survive a reboot
 */
module.exports = {
  apps: [
    {
      name: 'monadguard-api',
      script: 'server/index.js',
      instances: 1,
      autorestart: true,
      max_memory_restart: '300M',
      env: { NODE_ENV: 'production', PORT: 8787 },
      error_file: 'logs/api.err.log',
      out_file: 'logs/api.out.log',
      time: true,
    },
    {
      name: 'monadguard-worker',
      script: 'server/worker.js',
      instances: 1,
      autorestart: true,
      // A crash loop here means the chain or the key is wrong; hammering it
      // just floods the RPC quota. Back off hard and let the logs be read.
      restart_delay: 10_000,
      max_restarts: 10,
      env: { NODE_ENV: 'production' },
      error_file: 'logs/worker.err.log',
      out_file: 'logs/worker.out.log',
      time: true,
    },
  ],
};

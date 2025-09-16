// ------------------
// CONFIG
// ------------------
// Centralized configuration and environment validation
// - Validates required environment variables at startup
// - Exposes common config values used by server.js and other modules

const requiredEnvs = ['MONGO_URI', 'SESSION_SECRET'];
const missing = requiredEnvs.filter(k => !process.env[k]);
if (missing.length) {
  console.error('Missing required environment variables:', missing.join(', '));
  console.error('Create a .env file or set these variables in your environment. Exiting.');
  process.exit(1);
}

module.exports = {
  port: process.env.PORT ? Number(process.env.PORT) : 1986,
  mongoUri: process.env.MONGO_URI,
  sessionSecret: process.env.SESSION_SECRET,
  isProduction: process.env.NODE_ENV === 'production',
  siteTitle: 'LedgerLight',
  titleTemplate: '%s | LedgerLight'
};

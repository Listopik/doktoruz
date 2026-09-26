const { Pool } = require('pg');

let pool = global.__doktoruzPool;
if (!pool) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
    max: 5,
  });
  global.__doktoruzPool = pool;
}

async function query(text, params=[]) {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');
  return pool.query(text, params);
}

module.exports = { pool, query };

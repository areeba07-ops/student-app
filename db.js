const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.db.eajmdrghdoykrechzbyr.supabase.co,
  port: process.env.DB_PORT || 5432,
  user: process.env.postgres,
  password: process.env.veniatvidiat34,
  database: process.env.postgres,
  ssl: { rejectUnauthorized: false }
});

pool.connect((err) => {
  if (err) {
    console.log("❌ DB Error:", err);
  } else {
    console.log("✅ Connected to PostgreSQL");
  }
});

// This makes it work like mysql2 so you don't need to change server.js
pool.query = pool.query.bind(pool);

module.exports = {
  query: (sql, params, callback) => {
    // Convert MySQL ? placeholders to PostgreSQL $1, $2...
    let i = 0;
    const pgSql = sql.replace(/\?/g, () => `$${++i}`);
    pool.query(pgSql, params, (err, result) => {
      callback(err, result ? result.rows : null);
    });
  }
};
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect((err) => {
  if (err) {
    console.log("❌ DB Error:", err);
  } else {
    console.log("✅ Connected to PostgreSQL");
  }
});

module.exports = {
  query: (sql, params, callback) => {
    let i = 0;
    const pgSql = sql.replace(/\?/g, () => `$${++i}`);
    pool.query(pgSql, params, (err, result) => {
      callback(err, result ? result.rows : null);
    });
  }
};
const { Pool } = require('pg');

const pool = new Pool({
  host: 'aws-1-ap-south-1.pooler.supabase.com',
  port: 6543,
  user: 'postgres.eajmdrghdoykrechzbyr',
  password: 'veniatvidiat34',
  database: 'postgres',
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
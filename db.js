const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

pool.on("connect", () => {
  console.log("Connected to database");
});

pool.on("error", (err) => {
  console.error("Unexpected DB error:", err);
});

module.exports = {
  query: (text, params, callback) => {
    return pool.query(text, params, (err, result) => {
      if (callback) callback(err, result ? result.rows : []);
    });
  },
};
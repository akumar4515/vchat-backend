// db.js
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
dotenv.config();

const pool = mysql.createPool({
  host: 'mysql-25d80971-devloop.e.aivencloud.com',
  user: 'avnadmin',
  password: process.env.DB_PASSWORD, // 👈 fix here

  database: 'chat_app',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  port: 26372
});

export default pool;

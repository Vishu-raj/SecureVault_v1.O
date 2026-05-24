-- Migration: 0001_init.sql
-- Creates all tables for Secure Task Portal

CREATE TABLE IF NOT EXISTS users (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  username  TEXT    UNIQUE NOT NULL,
  email     TEXT    UNIQUE NOT NULL,
  password  TEXT    NOT NULL,
  role      TEXT    NOT NULL DEFAULT 'viewer',
  status    TEXT    NOT NULL DEFAULT 'Active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  token_hash TEXT    NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  action     TEXT NOT NULL,
  detail     TEXT,
  ip         TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

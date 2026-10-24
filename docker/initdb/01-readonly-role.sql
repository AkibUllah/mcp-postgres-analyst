-- Runs once when the Postgres volume is created. The MCP server connects as analyst_ro,
-- which can only read; the seed job (connecting as the owner "shop") grants SELECT on the
-- demo tables and revokes access to staff_payroll.
CREATE ROLE analyst_ro LOGIN PASSWORD 'analyst_ro'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE analyst_ro SET default_transaction_read_only = on;
ALTER ROLE analyst_ro SET statement_timeout = '10s';
GRANT CONNECT ON DATABASE shop TO analyst_ro;
GRANT USAGE ON SCHEMA public TO analyst_ro;

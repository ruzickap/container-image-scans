/* tsqllint-disable */
-- Container Image Scans - Supabase Database Schema
--
-- This is a convenience wrapper that applies all migrations in order.
-- The source of truth lives in supabase/migrations/.
--
-- Usage:
--   psql "$DATABASE_URL" -f supabase/schema.sql
--
-- For Supabase-hosted projects prefer the CLI instead:
--   supabase db push

\ir migrations/20250301000000_initial_schema.sql
\ir migrations/20250303000000_add_table_grants.sql

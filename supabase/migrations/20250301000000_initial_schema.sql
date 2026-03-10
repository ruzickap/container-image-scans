/* tsqllint-disable */
-- Container Image Scans - Initial Schema
-- Creates all tables, indexes, RLS policies, seed data, and
-- the pg_cron job for automatic data retention.

-- =============================================================
-- Table: image_groups
-- Stores logical groups of container images (e.g. python, node)
-- =============================================================
CREATE TABLE IF NOT EXISTS image_groups (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- =============================================================
-- Table: container_images
-- Stores individual container image references
-- =============================================================
CREATE TABLE IF NOT EXISTS container_images (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  image text NOT NULL UNIQUE,
  group_id bigint NOT NULL REFERENCES image_groups (id)
    ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_container_images_group
  ON container_images (group_id);

-- =============================================================
-- Table: scans
-- One row per scan execution (one image + one scanner + one run)
-- =============================================================
CREATE TABLE IF NOT EXISTS scans (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  container_image_id bigint NOT NULL REFERENCES container_images (id)
    ON DELETE CASCADE,
  scanner text NOT NULL CHECK (scanner IN ('trivy', 'grype')),
  image_digest text NOT NULL,
  scanner_version text NOT NULL,
  scanner_db_info text NOT NULL DEFAULT '',
  cve_count integer NOT NULL DEFAULT 0,
  sarif jsonb NOT NULL DEFAULT '{}'::jsonb,
  scanned_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_container_image
  ON scans (container_image_id);
CREATE INDEX IF NOT EXISTS idx_scans_scanner
  ON scans (scanner);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at
  ON scans (scanned_at);

-- =============================================================
-- Table: cves
-- Individual CVE entries extracted from SARIF results.
-- Linked to a scan so we can show per-day detail.
-- =============================================================
CREATE TABLE IF NOT EXISTS cves (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id bigint NOT NULL REFERENCES scans (id)
    ON DELETE CASCADE,
  cve_id text NOT NULL,
  severity text NOT NULL DEFAULT 'UNKNOWN',
  description text NOT NULL DEFAULT '',
  help_markdown text NOT NULL DEFAULT '',
  package_name text NOT NULL DEFAULT '',
  installed_version text NOT NULL DEFAULT '',
  fixed_version text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cves_scan ON cves (scan_id);
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves (cve_id);

-- =============================================================
-- Seed data: image groups and container images
-- =============================================================
INSERT INTO image_groups (name, description)
VALUES
  ('python', 'Python images (latest stable: 3.14)'),
  ('node', 'Node.js images (latest stable: 24)'),
  ('php', 'PHP images (latest stable: 8.5)'),
  ('nginx', 'Nginx images (latest stable: 1.28)'),
  ('ruby', 'Ruby images (latest stable: 4.0)'),
  ('base', 'Base OS images')
ON CONFLICT (name) DO NOTHING;

INSERT INTO container_images (image, group_id)
VALUES
  ('docker.io/python:alpine',
    (SELECT id FROM image_groups WHERE name = 'python')),
  ('gcr.io/distroless/python3-debian12:latest',
    (SELECT id FROM image_groups WHERE name = 'python')),
  ('cgr.dev/chainguard/python:latest',
    (SELECT id FROM image_groups WHERE name = 'python')),
  ('registry.access.redhat.com/ubi10/python-312-minimal:latest',
    (SELECT id FROM image_groups WHERE name = 'python')),
  ('docker.io/node:24-alpine',
    (SELECT id FROM image_groups WHERE name = 'node')),
  ('gcr.io/distroless/nodejs24-debian12:latest',
    (SELECT id FROM image_groups WHERE name = 'node')),
  ('cgr.dev/chainguard/node:latest',
    (SELECT id FROM image_groups WHERE name = 'node')),
  ('registry.access.redhat.com/ubi10/nodejs-24-minimal:latest',
    (SELECT id FROM image_groups WHERE name = 'node')),
  ('docker.io/php:alpine',
    (SELECT id FROM image_groups WHERE name = 'php')),
  ('cgr.dev/chainguard/php:latest',
    (SELECT id FROM image_groups WHERE name = 'php')),
  ('registry.access.redhat.com/ubi10/php-83:latest',
    (SELECT id FROM image_groups WHERE name = 'php')),
  ('docker.io/nginx:alpine',
    (SELECT id FROM image_groups WHERE name = 'nginx')),
  ('cgr.dev/chainguard/nginx:latest',
    (SELECT id FROM image_groups WHERE name = 'nginx')),
  ('registry.access.redhat.com/ubi10/nginx-126:latest',
    (SELECT id FROM image_groups WHERE name = 'nginx')),
  ('docker.io/ruby:alpine',
    (SELECT id FROM image_groups WHERE name = 'ruby')),
  ('cgr.dev/chainguard/ruby:latest',
    (SELECT id FROM image_groups WHERE name = 'ruby')),
  ('registry.access.redhat.com/ubi10/ruby-33:latest',
    (SELECT id FROM image_groups WHERE name = 'ruby')),
  ('docker.io/alpine:latest',
    (SELECT id FROM image_groups WHERE name = 'base')),
  ('docker.io/debian:stable-slim',
    (SELECT id FROM image_groups WHERE name = 'base')),
  ('docker.io/ubuntu:latest',
    (SELECT id FROM image_groups WHERE name = 'base')),
  ('gcr.io/distroless/static:latest',
    (SELECT id FROM image_groups WHERE name = 'base')),
  ('registry.access.redhat.com/ubi10-micro:latest',
    (SELECT id FROM image_groups WHERE name = 'base'))
ON CONFLICT (image) DO NOTHING;

-- =============================================================
-- Table-level GRANT permissions for PostgREST roles
-- =============================================================
GRANT SELECT ON image_groups TO anon;
GRANT SELECT ON container_images TO anon;
GRANT SELECT ON scans TO anon;
GRANT SELECT ON cves TO anon;

GRANT ALL ON image_groups TO service_role;
GRANT ALL ON container_images TO service_role;
GRANT ALL ON scans TO service_role;
GRANT ALL ON cves TO service_role;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO anon;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- =============================================================
-- Row Level Security (RLS) - allow public read, service write
-- =============================================================
ALTER TABLE image_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE container_images ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE cves ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public read image_groups"
  ON image_groups FOR SELECT USING (true);
CREATE POLICY "Public read container_images"
  ON container_images FOR SELECT USING (true);
CREATE POLICY "Public read scans"
  ON scans FOR SELECT USING (true);
CREATE POLICY "Public read cves"
  ON cves FOR SELECT USING (true);

CREATE POLICY "Service insert scans"
  ON scans FOR INSERT
  WITH CHECK (true);
CREATE POLICY "Service insert cves"
  ON cves FOR INSERT
  WITH CHECK (true);
CREATE POLICY "Service insert image_groups"
  ON image_groups FOR INSERT
  WITH CHECK (true);
CREATE POLICY "Service insert container_images"
  ON container_images FOR INSERT
  WITH CHECK (true);

-- =============================================================
-- Data retention: automatically delete scans older than 1 year.
-- Deleting from scans cascades to cves via ON DELETE CASCADE.
-- =============================================================
CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA pg_catalog;

CREATE OR REPLACE FUNCTION delete_old_scans()
RETURNS void
LANGUAGE plpgsql
AS '
DECLARE
  deleted_count bigint;
BEGIN
  DELETE FROM scans
  WHERE scanned_at < now() - INTERVAL ''1 year'';
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE LOG ''delete_old_scans: removed % scan(s)'', deleted_count;
END;
';

-- Run every Sunday at 01:00 UTC (after the nightly scan completes)
SELECT cron.schedule(
  'delete-old-scans',
  '0 1 * * 0',
  'SELECT delete_old_scans()'
);

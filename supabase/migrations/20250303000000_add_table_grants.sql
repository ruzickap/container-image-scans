/* tsqllint-disable */
-- Add table-level GRANT permissions for Supabase PostgREST roles.
-- Tables created via SQL migrations do not inherit the default
-- grants that the Supabase Dashboard applies automatically.

-- anon: read-only access (used by the web dashboard via anon key)
GRANT SELECT ON image_groups TO anon;
GRANT SELECT ON container_images TO anon;
GRANT SELECT ON scans TO anon;
GRANT SELECT ON cves TO anon;

-- service_role: read + write access (used by the scan script)
GRANT ALL ON image_groups TO service_role;
GRANT ALL ON container_images TO service_role;
GRANT ALL ON scans TO service_role;
GRANT ALL ON cves TO service_role;

-- Grant USAGE on sequences so INSERT with GENERATED ALWAYS works
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO anon;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO service_role;

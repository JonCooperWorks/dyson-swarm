-- Rename the Docker MCP template metadata column to match the product
-- language: admins define placeholders, users fill placeholder values.

ALTER TABLE mcp_docker_catalog
  RENAME COLUMN credentials_json TO placeholders_json;

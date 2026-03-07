-- Add org_id and claim_mapping to OIDC federation providers.

ALTER TABLE authx_oidc_federation_providers
    ADD COLUMN IF NOT EXISTS org_id         UUID        REFERENCES authx_orgs(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS claim_mapping  JSONB       NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_oidc_fed_providers_org_id
    ON authx_oidc_federation_providers(org_id) WHERE org_id IS NOT NULL;

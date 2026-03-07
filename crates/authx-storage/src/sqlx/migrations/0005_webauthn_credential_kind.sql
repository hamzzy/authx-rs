-- Add dedicated credential kind for WebAuthn/passkeys.
-- ADD VALUE IF NOT EXISTS is safe inside transactions on PG 12+.
ALTER TYPE authx_credential_kind ADD VALUE IF NOT EXISTS 'webauthn';

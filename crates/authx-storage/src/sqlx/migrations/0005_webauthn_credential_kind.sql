-- Add dedicated credential kind for WebAuthn/passkeys.
ALTER TYPE authx_credential_kind ADD VALUE IF NOT EXISTS 'webauthn';

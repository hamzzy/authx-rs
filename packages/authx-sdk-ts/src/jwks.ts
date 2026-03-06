import { AuthxSdkError } from "./errors.js";
import { requestJson } from "./http.js";
import { discoverIssuer } from "./oidc.js";

export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface OidcJwk extends JsonWebKey {
  kid?: string;
  use?: string;
  alg?: string;
  kty: string;
  x5c?: string[];
  [key: string]: unknown;
}

export interface JwksDocument {
  keys: OidcJwk[];
  [key: string]: unknown;
}

export interface SelectJwkOptions {
  kid?: string;
  alg?: string;
  use?: string;
  kty?: string;
}

export async function fetchJwks(jwksUri: string): Promise<JwksDocument> {
  return requestJson<JwksDocument>({
    path: jwksUri,
    method: "GET",
  });
}

export async function fetchIssuerJwks(issuer: string): Promise<JwksDocument> {
  const discovery = await discoverIssuer(issuer);

  if (!discovery.jwks_uri) {
    throw new AuthxSdkError("issuer discovery document does not include jwks_uri");
  }

  return fetchJwks(discovery.jwks_uri);
}

export function decodeJwtHeader(token: string): JwtHeader {
  const [encodedHeader] = token.split(".");

  if (!encodedHeader) {
    throw new AuthxSdkError("JWT header is missing");
  }

  let parsed: unknown;
  try {
    const headerJson = new TextDecoder().decode(decodeBase64Url(encodedHeader));
    parsed = JSON.parse(headerJson);
  } catch (error) {
    throw new AuthxSdkError("JWT header could not be decoded", { details: error });
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AuthxSdkError("JWT header must decode to an object", { details: parsed });
  }

  return parsed as JwtHeader;
}

export function selectJwk(jwks: JwksDocument, options: SelectJwkOptions): OidcJwk | undefined {
  let candidates = [...jwks.keys];

  if (options.kid) {
    candidates = candidates.filter((key) => key.kid === options.kid);
  }
  if (options.kty) {
    candidates = candidates.filter((key) => key.kty === options.kty);
  }

  candidates = narrowPreferredValue(candidates, "use", options.use);
  candidates = narrowPreferredValue(candidates, "alg", options.alg);

  return candidates[0];
}

export function getJwkForJwt(jwks: JwksDocument, token: string): OidcJwk | undefined {
  const header = decodeJwtHeader(token);

  return selectJwk(jwks, {
    kid: typeof header.kid === "string" ? header.kid : undefined,
    alg: typeof header.alg === "string" ? header.alg : undefined,
    use: "sig",
  });
}

function narrowPreferredValue<K extends "alg" | "use">(
  keys: OidcJwk[],
  field: K,
  expected: string | undefined,
): OidcJwk[] {
  if (!expected) {
    return keys;
  }

  const exact = keys.filter((key) => key[field] === expected);
  if (exact.length > 0) {
    return exact;
  }

  return keys.filter((key) => key[field] === undefined);
}

function decodeBase64Url(input: string): Uint8Array {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  const source = normalized + "=".repeat(paddingLength);
  const bytes: number[] = [];

  let buffer = 0;
  let bits = 0;

  for (const char of source) {
    if (char === "=") {
      break;
    }

    const value = BASE64_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new AuthxSdkError(`invalid base64url character: ${char}`);
    }

    buffer = (buffer << 6) | value;
    bits += 6;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }

  return Uint8Array.from(bytes);
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

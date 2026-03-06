import { AuthxSdkError } from "./errors";

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function webCrypto(): Crypto {
  const cryptoImpl = globalThis.crypto;
  if (!cryptoImpl?.getRandomValues || !cryptoImpl.subtle) {
    throw new AuthxSdkError("Web Crypto support is required for PKCE helpers");
  }
  return cryptoImpl;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let output = "";
  let index = 0;

  while (index < bytes.length) {
    const a = bytes[index++] ?? 0;
    const b = bytes[index++] ?? 0;
    const c = bytes[index++] ?? 0;

    const triple = (a << 16) | (b << 8) | c;
    const remaining = bytes.length - (index - 3);

    output += BASE64URL_ALPHABET[(triple >> 18) & 0x3f];
    output += BASE64URL_ALPHABET[(triple >> 12) & 0x3f];
    output += remaining > 1 ? BASE64URL_ALPHABET[(triple >> 6) & 0x3f] : "";
    output += remaining > 2 ? BASE64URL_ALPHABET[triple & 0x3f] : "";
  }

  return output;
}

export function randomString(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  webCrypto().getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function createPkcePair(byteLength = 32): Promise<PkcePair> {
  const codeVerifier = randomString(byteLength);
  const digest = await webCrypto().subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  const codeChallenge = base64UrlEncode(new Uint8Array(digest));

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256",
  };
}

export function randomState(byteLength = 16): string {
  return randomString(byteLength);
}

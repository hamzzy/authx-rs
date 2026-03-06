export class AuthxTokenManagerError extends Error {
  readonly cause?: unknown;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = "AuthxTokenManagerError";
    this.cause = options?.cause;
  }
}

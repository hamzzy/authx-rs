export interface AuthxErrorBody {
  error?: string;
  message?: string;
  error_description?: string;
  [key: string]: unknown;
}

export class AuthxSdkError extends Error {
  readonly status?: number;
  readonly code?: string;
  readonly details?: unknown;

  constructor(message: string, options?: { status?: number; code?: string; details?: unknown }) {
    super(message);
    this.name = "AuthxSdkError";
    this.status = options?.status;
    this.code = options?.code;
    this.details = options?.details;
  }
}

export function toAuthxSdkError(
  message: string,
  options?: { status?: number; code?: string; details?: unknown },
): AuthxSdkError {
  return new AuthxSdkError(message, options);
}

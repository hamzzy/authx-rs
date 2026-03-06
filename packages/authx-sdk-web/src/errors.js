export class AuthxTokenManagerError extends Error {
    constructor(message, options) {
        super(message);
        this.name = "AuthxTokenManagerError";
        this.cause = options?.cause;
    }
}

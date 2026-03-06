import { AuthxTokenManagerError } from "./errors.js";
export class MemoryTokenStore {
    constructor(initialValue = null) {
        this.value = initialValue ? { ...initialValue } : null;
    }
    load() {
        return this.value ? { ...this.value } : null;
    }
    save(tokens) {
        this.value = tokens ? { ...tokens } : null;
    }
}
export class BrowserStorageTokenStore {
    constructor(options = {}) {
        this.key = options.key ?? "authx.tokens";
        this.storageImpl = options.storage;
    }
    load() {
        const raw = this.storage().getItem(this.key);
        if (!raw) {
            return null;
        }
        try {
            const parsed = JSON.parse(raw);
            return parsed && typeof parsed === "object" ? parsed : null;
        }
        catch (error) {
            throw new AuthxTokenManagerError("token storage contains invalid JSON", { cause: error });
        }
    }
    save(tokens) {
        const storage = this.storage();
        if (!tokens) {
            storage.removeItem(this.key);
            return;
        }
        storage.setItem(this.key, JSON.stringify(tokens));
    }
    storage() {
        if (this.storageImpl) {
            return this.storageImpl;
        }
        if ("localStorage" in globalThis && globalThis.localStorage) {
            return globalThis.localStorage;
        }
        throw new AuthxTokenManagerError("localStorage is not available in this runtime");
    }
}

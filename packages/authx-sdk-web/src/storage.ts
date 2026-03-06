import { AuthxTokenManagerError } from "./errors.js";
import type { StoredTokenState } from "./token-manager.js";

export interface TokenStore {
  load(): StoredTokenState | null | Promise<StoredTokenState | null>;
  save(tokens: StoredTokenState | null): void | Promise<void>;
}

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface BrowserStorageTokenStoreOptions {
  key?: string;
  storage?: StorageLike;
}

export class MemoryTokenStore implements TokenStore {
  private value: StoredTokenState | null;

  constructor(initialValue: StoredTokenState | null = null) {
    this.value = initialValue ? { ...initialValue } : null;
  }

  load(): StoredTokenState | null {
    return this.value ? { ...this.value } : null;
  }

  save(tokens: StoredTokenState | null): void {
    this.value = tokens ? { ...tokens } : null;
  }
}

export class BrowserStorageTokenStore implements TokenStore {
  private readonly key: string;
  private readonly storageImpl?: StorageLike;

  constructor(options: BrowserStorageTokenStoreOptions = {}) {
    this.key = options.key ?? "authx.tokens";
    this.storageImpl = options.storage;
  }

  load(): StoredTokenState | null {
    const raw = this.storage().getItem(this.key);
    if (!raw) {
      return null;
    }

    try {
      const parsed = JSON.parse(raw) as StoredTokenState;
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (error) {
      throw new AuthxTokenManagerError("token storage contains invalid JSON", { cause: error });
    }
  }

  save(tokens: StoredTokenState | null): void {
    const storage = this.storage();

    if (!tokens) {
      storage.removeItem(this.key);
      return;
    }

    storage.setItem(this.key, JSON.stringify(tokens));
  }

  private storage(): StorageLike {
    if (this.storageImpl) {
      return this.storageImpl;
    }

    if ("localStorage" in globalThis && globalThis.localStorage) {
      return globalThis.localStorage;
    }

    throw new AuthxTokenManagerError("localStorage is not available in this runtime");
  }
}

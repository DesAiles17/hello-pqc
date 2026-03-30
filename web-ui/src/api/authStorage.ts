const API_KEY_STORAGE_KEY = 'pqc_api_key';
const API_KEY_LAST_USED_STORAGE_KEY = 'pqc_api_key_last_used_at';

function maxAgeMs(): number {
    const minutes = Number(import.meta.env.VITE_API_KEY_MAX_AGE_MINUTES ?? 30);
    if (!Number.isFinite(minutes) || minutes <= 0) {
        return 30 * 60 * 1000;
    }
    return Math.min(minutes, 480) * 60 * 1000;
}

function now(): number {
    return Date.now();
}

export function clearApiKey(): void {
    sessionStorage.removeItem(API_KEY_STORAGE_KEY);
    sessionStorage.removeItem(API_KEY_LAST_USED_STORAGE_KEY);
}

export function setApiKey(key: string): void {
    sessionStorage.setItem(API_KEY_STORAGE_KEY, key);
    sessionStorage.setItem(API_KEY_LAST_USED_STORAGE_KEY, String(now()));
}

export function touchApiKeySession(): void {
    if (!sessionStorage.getItem(API_KEY_STORAGE_KEY)) {
        clearApiKey();
        return;
    }
    sessionStorage.setItem(API_KEY_LAST_USED_STORAGE_KEY, String(now()));
}

export function getApiKey(): string | null {
    const key = sessionStorage.getItem(API_KEY_STORAGE_KEY);
    if (!key) {
        clearApiKey();
        return null;
    }

    const lastUsedRaw = sessionStorage.getItem(API_KEY_LAST_USED_STORAGE_KEY);
    const lastUsed = lastUsedRaw ? Number(lastUsedRaw) : NaN;

    if (!Number.isFinite(lastUsed)) {
        clearApiKey();
        return null;
    }

    if (now() - lastUsed > maxAgeMs()) {
        clearApiKey();
        return null;
    }

    return key;
}

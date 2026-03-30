export function getSafeErrorMessage(error: any, fallback: string): string {
    const status = error?.response?.status;

    if (status === 400) return 'Invalid request. Please check your inputs.';
    if (status === 401 || status === 403) return 'Authentication failed. Please re-enter your API key.';
    if (status === 404) return 'Requested resource was not found.';
    if (status === 413) return 'File is too large for this service.';
    if (status === 429) return 'Rate limit exceeded. Please wait and try again.';
    if (status >= 500) return 'Server error occurred. Please try again shortly.';

    if (error?.code === 'ERR_NETWORK' || error?.code === 'ECONNABORTED') {
        return 'Network issue detected. Please retry.';
    }

    return fallback;
}
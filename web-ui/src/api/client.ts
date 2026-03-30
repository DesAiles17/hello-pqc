import axios from 'axios';
import { clearApiKey, getApiKey, touchApiKeySession } from './authStorage';

const apiClient = axios.create({
    baseURL: '/api',
    timeout: 30000,
});

// Add API key to all requests
apiClient.interceptors.request.use((config) => {
    const apiKey = getApiKey();

    if (apiKey) {
        config.headers['X-API-Key'] = apiKey;
        touchApiKeySession();
    }

    return config;
});

// Handle authentication errors
apiClient.interceptors.response.use(
    (response) => response,
    async (error) => {
        const config = error.config;
        const url = (config?.url || '').toLowerCase();
        const isCryptoOperation =
            url.includes('/verify') ||
            url.includes('/process') ||
            url.includes('/upload');

        // Check if error is retryable
        const isRetryable = (err: any): boolean => {
            if (err.code === 'ERR_NETWORK' || err.code === 'ECONNABORTED') {
                return true;
            }
            if (err.response?.status >= 500) {
                return true;
            }
            if (err.response?.status === 429) {
                return true;
            }
            return false;
        };

        // Retry logic with exponential backoff
        if (isRetryable(error) && config && !config._retry && !isCryptoOperation) {
            config._retry = (config._retry || 0) + 1;

            if (config._retry <= 3) {
                const delay = Math.pow(2, config._retry - 1) * 1000;
                await new Promise((resolve) => setTimeout(resolve, delay));
                return apiClient(config);
            }
        }

        // Handle auth failures
        if (error.response?.status === 401 || error.response?.status === 403) {
            clearApiKey();
            // Could redirect to settings page here
        }

        return Promise.reject(error);
    }
);

export default apiClient;

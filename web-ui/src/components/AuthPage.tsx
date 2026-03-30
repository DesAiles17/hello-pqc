import { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import toast from 'react-hot-toast';
import axios from 'axios';

interface AuthPageProps {
    onAuthenticated: () => void;
}

export default function AuthPage({ onAuthenticated }: AuthPageProps) {
    const { setApiKey } = useAuth();
    const [inputValue, setInputValue] = useState('');
    const [showKey, setShowKey] = useState(false);
    const [validating, setValidating] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        if (!inputValue.trim()) {
            toast.error('Please enter an API key');
            return;
        }

        const apiKey = inputValue.trim();

        // Validate API key against /health endpoint
        setValidating(true);
        try {
            const response = await axios.get('/api/health', {
                headers: {
                    'X-API-Key': apiKey,
                },
                timeout: 5000,
            });

            // If we get a 200, the key is valid
            if (response.status === 200) {
                setApiKey(apiKey);
                setInputValue('');
                toast.success('API key validated successfully');
                onAuthenticated();
            }
        } catch (err: any) {
            if (err.response?.status === 401 || err.response?.status === 403) {
                const errorMsg = 'Invalid API key. Please check your credentials.';
                setError(errorMsg);
                toast.error(errorMsg);
            } else if (err.code === 'ERR_NETWORK' || err.code === 'ECONNABORTED') {
                const errorMsg = 'Unable to reach server. Please try again.';
                setError(errorMsg);
                toast.error(errorMsg);
            } else {
                const errorMsg = 'Validation failed. Please try again.';
                setError(errorMsg);
                toast.error(errorMsg);
            }
        } finally {
            setValidating(false);
        }
    };

    return (
        <div className="min-h-screen flex flex-col bg-gradient-to-br from-neutral-50 to-neutral-100">
            <div className="flex-1 flex items-center justify-center px-4 py-8">
                <div className="w-full max-w-md">
                    {/* Header */}
                    <div className="text-center mb-12">
                        <h1 className="text-3xl font-semibold text-neutral-900 mb-3 tracking-tight">
                            PQC File Signing
                        </h1>
                        <p className="text-base text-neutral-600">
                            Post-Quantum Cryptography Research Tool
                        </p>
                    </div>

                    {/* Auth Form */}
                    <form onSubmit={handleSubmit} className="bg-white border border-neutral-200 rounded-lg shadow-sm p-8">
                        <div className="mb-6">
                            <label htmlFor="apiKey" className="block text-sm font-medium text-neutral-900 mb-3">
                                API Key
                            </label>
                            <div className="flex gap-2">
                                <input
                                    id="apiKey"
                                    type={showKey ? 'text' : 'password'}
                                    value={inputValue}
                                    onChange={(e) => {
                                        setInputValue(e.target.value);
                                        setError(null);
                                    }}
                                    placeholder="Enter your API key"
                                    className="flex-1 px-4 py-2.5 border border-neutral-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors font-mono"
                                    autoFocus
                                    disabled={validating}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowKey(!showKey)}
                                    className="px-3.5 py-2.5 bg-neutral-100 border border-neutral-300 rounded-md text-sm font-medium text-neutral-700 hover:bg-neutral-200 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                    title={showKey ? 'Hide API key' : 'Show API key'}
                                    disabled={validating}
                                >
                                    {showKey ? 'Hide' : 'Show'}
                                </button>
                            </div>
                            {error && (
                                <p className="mt-2 text-sm text-red-600">
                                    {error}
                                </p>
                            )}
                        </div>

                        <button
                            type="submit"
                            disabled={validating}
                            className="w-full bg-primary-600 text-white py-2.5 rounded-md text-sm font-semibold hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {validating ? 'Validating...' : 'Continue'}
                        </button>
                    </form>

                    {/* Footer Info */}
                    <div className="mt-8 text-center">
                        <p className="text-xs text-neutral-500 mb-3">
                            Honours Project - Anna Kudrych
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}

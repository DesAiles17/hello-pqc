import React, { createContext, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { clearApiKey, getApiKey, setApiKey as persistApiKey } from '../api/authStorage';

interface AuthContextType {
    apiKey: string | null;
    gatewayUrl: string;
    setApiKey: (key: string) => void;
    setGatewayUrl: (url: string) => void;
    clearAuth: () => void;
    isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [apiKey, setApiKeyState] = useState<string | null>(() => {
        return getApiKey();
    });

    const [gatewayUrl, setGatewayUrlState] = useState<string>(() => {
        return localStorage.getItem('pqc_gateway_url') || 'http://localhost:3000';
    });

    const setApiKey = (key: string) => {
        persistApiKey(key);
        setApiKeyState(key);
    };

    const setGatewayUrl = (url: string) => {
        localStorage.setItem('pqc_gateway_url', url);
        setGatewayUrlState(url);
    };

    const clearAuth = () => {
        clearApiKey();
        setApiKeyState(null);
    };

    useEffect(() => {
        const sync = () => {
            setApiKeyState(getApiKey());
        };

        const intervalId = window.setInterval(sync, 60_000);
        window.addEventListener('focus', sync);
        document.addEventListener('visibilitychange', sync);

        return () => {
            window.clearInterval(intervalId);
            window.removeEventListener('focus', sync);
            document.removeEventListener('visibilitychange', sync);
        };
    }, []);

    const value: AuthContextType = {
        apiKey,
        gatewayUrl,
        setApiKey,
        setGatewayUrl,
        clearAuth,
        isAuthenticated: !!apiKey,
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within AuthProvider');
    }
    return context;
};

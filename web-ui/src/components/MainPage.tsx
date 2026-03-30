import { useAuth } from '../contexts/AuthContext';
import toast from 'react-hot-toast';

interface MainPageProps {
    onNavigate: (page: 'sign' | 'verify' | 'settings') => void;
}

export default function MainPage({ onNavigate }: MainPageProps) {
    const { clearAuth } = useAuth();

    const handleLogout = () => {
        clearAuth();
        toast.success('API key cleared');
    };

    return (
        <div className="min-h-screen flex flex-col bg-neutral-50">
            <header className="bg-white border-b border-neutral-200">
                <div className="max-w-screen-lg mx-auto px-8 py-4 flex justify-between items-center">
                    <h1 className="text-xl font-semibold text-neutral-900 tracking-tight">PQC File Signing</h1>
                    <button
                        onClick={handleLogout}
                        className="px-3 py-1.5 text-sm text-neutral-600 hover:text-neutral-900 hover:bg-neutral-100 rounded-md transition-colors"
                    >
                        Change Key
                    </button>
                </div>
            </header>

            <main className="flex-1 flex items-center justify-center px-4 py-12">
                <div className="w-full max-w-2xl">
                    {/* Title */}
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-semibold text-neutral-900 mb-2">What would you like to do?</h2>
                        <p className="text-base text-neutral-600">Choose an action below</p>
                    </div>

                    {/* Action Buttons */}
                    <div className="grid grid-cols-2 gap-6 mb-8">
                        {/* Sign Button */}
                        <button
                            onClick={() => onNavigate('sign')}
                            className="flex flex-col items-center justify-center aspect-square bg-white border-2 border-neutral-200 rounded-lg hover:border-primary-500 hover:shadow-lg transition-all p-8"
                        >
                            <div className="w-12 h-12 bg-primary-100 rounded-lg mb-4 flex items-center justify-center">
                                <span className="text-lg text-primary-600 font-semibold">✎</span>
                            </div>
                            <h3 className="text-lg font-semibold text-neutral-900 mb-2">Sign File</h3>
                            <p className="text-sm text-neutral-600 text-center">
                                Upload and sign files
                            </p>
                        </button>

                        {/* Verify Button */}
                        <button
                            onClick={() => onNavigate('verify')}
                            className="flex flex-col items-center justify-center aspect-square bg-white border-2 border-neutral-200 rounded-lg hover:border-primary-500 hover:shadow-lg transition-all p-8"
                        >
                            <div className="w-12 h-12 bg-success-100 rounded-lg mb-4 flex items-center justify-center">
                                <span className="text-lg text-success-600 font-semibold">✓</span>
                            </div>
                            <h3 className="text-lg font-semibold text-neutral-900 mb-2">Verify Signature</h3>
                            <p className="text-sm text-neutral-600 text-center">
                                Check a manifest
                            </p>
                        </button>
                    </div>

                    {/* Settings Button */}
                    <div className="flex justify-center">
                        <button
                            onClick={() => onNavigate('settings')}
                            className="px-6 py-2 text-sm text-neutral-600 hover:text-neutral-900 hover:bg-neutral-200 rounded-md transition-colors font-medium"
                        >
                            Settings
                        </button>
                    </div>
                </div>
            </main>

            <footer className="bg-white border-t border-neutral-200 px-8 py-4 text-center mt-auto">
                <p className="text-xs text-neutral-600">
                    Honours Project - Anna Kudrych
                </p>
            </footer>
        </div>
    );
}

import { useState } from 'react';
import apiClient from '../api/client';
import toast from 'react-hot-toast';
import FileUploadZone from './FileUploadZone';
import type { FileMetadata, VerificationCheck, VerificationMetadata } from '../types';
import { getSafeErrorMessage } from '../api/errors';

interface VerifyPageProps {
    onBack: () => void;
}

interface VerifyResponse {
    request_id: string;
    signature_ok: boolean;
    object_ok?: boolean;
    file_hash_match: boolean;
    overall_ok: boolean;
    errors: string[];
    checks?: VerificationCheck[];
    metadata?: VerificationMetadata;
}

export default function VerifyPage({ onBack }: VerifyPageProps) {
    const [requestId, setRequestId] = useState('');
    const [uploadedFilePath, setUploadedFilePath] = useState<string | null>(null);
    const [uploadedFileMeta, setUploadedFileMeta] = useState<FileMetadata | null>(null);
    const [verifying, setVerifying] = useState(false);
    const [result, setResult] = useState<VerifyResponse | null>(null);

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!requestId.trim()) {
            toast.error('Please enter a request ID');
            return;
        }

        if (!uploadedFilePath) {
            toast.error('Please upload a file before verification');
            return;
        }

        // Validate UUID format
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(requestId)) {
            toast.error('Invalid request ID format');
            return;
        }

        setVerifying(true);
        const toastId = toast.loading('Verifying signature...');

        try {
            const response = await apiClient.post('/verify', {
                request_id: requestId,
                verify_object: true,
                file_path: uploadedFilePath,
            });

            setResult(response.data);
            toast.success('Verification complete!', { id: toastId });
        } catch (error: any) {
            const errorMsg = getSafeErrorMessage(error, 'Verification failed');
            toast.error(errorMsg, { id: toastId });
        } finally {
            setVerifying(false);
        }
    };

    return (
        <div className="min-h-screen flex flex-col bg-neutral-50">
            <header className="bg-white border-b border-neutral-200">
                <div className="max-w-screen-lg mx-auto px-8 py-4">
                    <button
                        onClick={onBack}
                        className="text-sm font-medium text-primary-600 hover:text-primary-700 flex items-center gap-1 mb-4"
                    >
                        ← Back
                    </button>
                    <h1 className="text-2xl font-semibold text-neutral-900">Verify Signature</h1>
                </div>
            </header>

            <main className="flex-1 max-w-screen-lg mx-auto px-8 py-8 w-full">
                {!result && (
                    <div className="space-y-8">
                        {/* File Upload Section */}
                        <div className="bg-white border border-neutral-200 rounded-lg p-8">
                            <h2 className="text-lg font-medium text-neutral-900 mb-6">Step 1: Upload File</h2>
                            <p className="text-sm text-neutral-600 mb-4">
                                Upload the verification file first. This is required before request ID verification.
                            </p>
                            <FileUploadZone
                                onFileUploaded={(filePath, metadata) => {
                                    setUploadedFilePath(filePath);
                                    setUploadedFileMeta(metadata);
                                }}
                            />
                            {uploadedFilePath && (
                                <div className="mt-4 bg-success-100 border-l-4 border-success-600 px-4 py-3 rounded text-sm text-neutral-900">
                                    <span className="font-medium">File uploaded:</span>{' '}
                                    {uploadedFileMeta?.originalName || 'Uploaded file'}
                                </div>
                            )}
                        </div>

                        {/* Request ID Section */}
                        <div className={`bg-white border border-neutral-200 rounded-lg p-8 ${!uploadedFilePath ? 'opacity-60' : ''}`}>
                            <h2 className="text-lg font-medium text-neutral-900 mb-6">Step 2: Enter Request ID</h2>
                            {!uploadedFilePath && (
                                <p className="text-sm text-neutral-600 mb-4">
                                    Complete Step 1 to enable request ID verification.
                                </p>
                            )}
                            <form onSubmit={handleVerify} className="space-y-4">
                                <div>
                                    <label htmlFor="requestId" className="block text-sm font-medium text-neutral-900 mb-2">
                                        Request ID
                                    </label>
                                    <input
                                        id="requestId"
                                        type="text"
                                        value={requestId}
                                        onChange={(e) => setRequestId(e.target.value)}
                                        placeholder="Enter request ID (UUID)"
                                        className="w-full px-4 py-2.5 border border-neutral-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors font-mono"
                                        autoFocus
                                        disabled={!uploadedFilePath || verifying}
                                    />
                                    <p className="mt-2 text-xs text-neutral-500">
                                        Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
                                    </p>
                                </div>

                                <button
                                    type="submit"
                                    disabled={verifying || !uploadedFilePath}
                                    className="w-full bg-primary-600 text-white py-2.5 rounded-md text-sm font-semibold hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                                >
                                    {verifying ? 'Verifying...' : 'Verify Signature'}
                                </button>
                            </form>
                        </div>
                    </div>
                )}

                {result && (
                    <div className="max-w-2xl mx-auto space-y-6">
                        {/* Overall Status with Icon */}
                        <div className="bg-white border border-neutral-200 rounded-md p-8 text-center">
                            <div
                                className={`w-20 h-20 rounded-full mx-auto mb-4 flex items-center justify-center ${result.overall_ok
                                    ? 'bg-success-100'
                                    : 'bg-error-100'
                                    }`}
                            >
                                <span
                                    className={`text-4xl ${result.overall_ok ? 'text-success-600' : 'text-error-600'
                                        }`}
                                >
                                    {result.overall_ok ? '✓' : '✗'}
                                </span>
                            </div>
                            <h2
                                className={`text-2xl font-semibold mb-3 ${result.overall_ok ? 'text-success-900' : 'text-error-900'
                                    }`}
                            >
                                {result.overall_ok ? 'Verification Passed' : 'Verification Failed'}
                            </h2>
                            <p className={`text-base ${result.overall_ok ? 'text-success-700' : 'text-error-700'}`}>
                                {result.overall_ok
                                    ? 'The signature is valid and the file has not been modified.'
                                    : 'One or more verification checks failed. See details below.'}
                            </p>
                        </div>

                        {/* Failed Checks Summary (if any) */}
                        {result.checks && result.checks.filter(c => !c.passed).length > 0 && (
                            <div className="bg-error-50 border-l-4 border-error-600 rounded-md p-6">
                                <h3 className="text-lg font-semibold text-error-900 mb-4">
                                    Failed Checks ({result.checks.filter(c => !c.passed).length})
                                </h3>
                                <div className="space-y-3">
                                    {result.checks.filter(c => !c.passed).map((check, idx) => (
                                        <div key={idx} className="bg-white rounded-md p-4 border border-error-200">
                                            <div className="flex items-start gap-3">
                                                <div className="flex-shrink-0 w-5 h-5 rounded-full bg-error-600 flex items-center justify-center text-white text-xs font-bold">
                                                    ✗
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-xs font-mono text-neutral-600 mb-1">
                                                        {check.name}
                                                    </p>
                                                    <p className="text-sm font-medium text-error-900">
                                                        {check.details}
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Errors List (if any from legacy) */}
                        {result.errors && result.errors.length > 0 && (
                            <div className="bg-warning-50 border border-warning-200 rounded-md p-6">
                                <h3 className="text-sm font-semibold text-warning-900 mb-3">Additional Errors</h3>
                                <ul className="space-y-2">
                                    {result.errors.map((error, idx) => (
                                        <li key={idx} className="text-sm text-warning-800 flex items-start gap-2">
                                            <span className="text-warning-600">•</span>
                                            <span>{error}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        {/* Detailed Checks */}
                        {result.checks && result.checks.length > 0 && (
                            <div className="bg-white border border-neutral-200 rounded-md p-6">
                                <h3 className="text-lg font-semibold text-neutral-900 mb-4">
                                    All Verification Checks ({result.checks.length})
                                </h3>
                                <div className="space-y-2">
                                    {result.checks.map((check, idx) => (
                                        <div
                                            key={idx}
                                            className={`flex items-start gap-3 p-3 rounded-md border ${check.passed
                                                ? 'bg-success-50 border-success-200'
                                                : 'bg-error-50 border-error-200'
                                                }`}
                                        >
                                            <div
                                                className={`flex-shrink-0 w-4 h-4 rounded-full flex items-center justify-center text-white text-xs font-bold ${check.passed ? 'bg-success-600' : 'bg-error-600'
                                                    }`}
                                            >
                                                {check.passed ? '✓' : '✗'}
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <p className="text-xs font-mono text-neutral-600 mb-1">
                                                    {check.name}
                                                </p>
                                                <p className={`text-sm ${check.passed ? 'text-success-900' : 'text-error-900'
                                                    }`}>
                                                    {check.details}
                                                </p>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Manifest Metadata */}
                        {result.metadata && (
                            <div className="bg-neutral-50 border border-neutral-200 rounded-md p-6">
                                <h3 className="text-lg font-semibold text-neutral-900 mb-4">
                                    Manifest Metadata
                                </h3>
                                <dl className="grid grid-cols-2 gap-x-6 gap-y-4">
                                    <div>
                                        <dt className="text-xs font-medium text-neutral-600 mb-1">Signature Profile</dt>
                                        <dd className="text-sm font-mono text-neutral-900">{result.metadata.signature_profile}</dd>
                                    </div>
                                    <div>
                                        <dt className="text-xs font-medium text-neutral-600 mb-1">Hash Algorithm</dt>
                                        <dd className="text-sm font-mono text-neutral-900">{result.metadata.hash_algorithm}</dd>
                                    </div>
                                    <div className="col-span-2">
                                        <dt className="text-xs font-medium text-neutral-600 mb-1">Canonical Manifest Hash</dt>
                                        <dd className="text-xs font-mono text-neutral-700 break-all">{result.metadata.canonical_manifest_hash}</dd>
                                    </div>
                                    <div>
                                        <dt className="text-xs font-medium text-neutral-600 mb-1">Created At</dt>
                                        <dd className="text-sm font-mono text-neutral-900">
                                            {new Date(result.metadata.manifest_created_at).toLocaleString()}
                                        </dd>
                                    </div>
                                    <div>
                                        <dt className="text-xs font-medium text-neutral-600 mb-1">File Size</dt>
                                        <dd className="text-sm font-mono text-neutral-900">
                                            {(result.metadata.manifest_size / 1024).toFixed(2)} KB
                                        </dd>
                                    </div>
                                    <div>
                                        <dt className="text-xs font-medium text-neutral-600 mb-1">Storage Bucket</dt>
                                        <dd className="text-sm font-mono text-neutral-900">{result.metadata.storage_bucket}</dd>
                                    </div>
                                    <div>
                                        <dt className="text-xs font-medium text-neutral-600 mb-1">Storage Key</dt>
                                        <dd className="text-xs font-mono text-neutral-700 break-all">{result.metadata.storage_key}</dd>
                                    </div>
                                </dl>
                            </div>
                        )}

                        {/* Request ID */}
                        <div className="bg-neutral-50 border border-neutral-200 rounded-md p-4">
                            <p className="text-xs font-medium text-neutral-600 mb-2">Request ID</p>
                            <p className="font-mono text-sm text-neutral-900 break-all">{result.request_id}</p>
                        </div>

                        {/* Actions */}
                        <div className="flex gap-3">
                            <button
                                onClick={() => {
                                    setResult(null);
                                    setRequestId('');
                                    setUploadedFilePath(null);
                                    setUploadedFileMeta(null);
                                }}
                                className="flex-1 px-6 py-3 bg-primary-600 text-white rounded-md text-base font-medium hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 transition-colors"
                            >
                                Verify Another
                            </button>
                            <button
                                onClick={onBack}
                                className="flex-1 px-6 py-3 bg-neutral-600 text-white rounded-md text-base font-medium hover:bg-neutral-700 focus:outline-none focus:ring-2 focus:ring-neutral-500 focus:ring-offset-2 transition-colors"
                            >
                                Back to Home
                            </button>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
}

import { useState } from 'react';
import type { SignedManifest } from '../types';
import toast from 'react-hot-toast';

interface ManifestViewerProps {
    manifest: SignedManifest;
}

const ManifestViewer: React.FC<ManifestViewerProps> = ({ manifest }) => {
    const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
        metadata: true,
        file_info: true,
        signatures: true,
    });

    const toggleSection = (section: string) => {
        setExpandedSections((prev) => ({
            ...prev,
            [section]: !prev[section],
        }));
    };

    const copyToClipboard = (fieldName: string, value: string) => {
        navigator.clipboard.writeText(value);
        toast.success(`Copied ${fieldName}`);
    };

    const downloadManifest = () => {
        const json = JSON.stringify(manifest, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `manifest-${manifest.core.request_id}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success('Manifest downloaded');
    };

    interface FieldProps {
        label: string;
        value: string;
        mono?: boolean;
        copyable?: boolean;
    }

    const Field: React.FC<FieldProps> = ({ label, value, mono = false, copyable = true }) => (
        <div className="mb-4 pb-4 border-b border-neutral-100 last:border-b-0 last:mb-0 last:pb-0">
            <label className="block text-xs font-medium text-neutral-600 mb-2 uppercase tracking-wider">
                {label}
            </label>
            <div className="flex justify-between items-start gap-4">
                <span className={`flex-1 break-all text-base text-neutral-900 ${mono ? 'font-mono bg-neutral-50 p-3 rounded' : ''}`}>
                    {value}
                </span>
                {copyable && (
                    <button
                        onClick={() => copyToClipboard(label, value)}
                        className="flex-shrink-0 bg-neutral-100 border border-neutral-300 px-3 py-2 rounded-sm text-sm font-medium hover:bg-neutral-200 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-colors"
                        title="Copy to clipboard"
                    >
                        Copy
                    </button>
                )}
            </div>
        </div>
    );

    return (
        <div className="border border-neutral-200 rounded-md bg-white">
            <div className="flex justify-between items-center border-b border-neutral-200 px-6 py-4">
                <h2 className="text-xl font-medium text-neutral-900">File Signed Successfully</h2>
                <button
                    onClick={downloadManifest}
                    className="bg-neutral-100 border border-neutral-300 px-4 py-2 rounded-sm text-sm font-medium hover:bg-neutral-200 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-colors"
                >
                    Download JSON
                </button>
            </div>

            <div className="p-6 space-y-4">
                {/* Metadata Section */}
                <section className="border border-neutral-200 rounded-md overflow-hidden">
                    <div
                        className="bg-neutral-100 px-4 py-3 cursor-pointer hover:bg-neutral-200 transition-colors focus:outline-none"
                        onClick={() => toggleSection('metadata')}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                toggleSection('metadata');
                            }
                        }}
                    >
                        <h3 className="text-base font-medium text-neutral-900">
                            <span className="mr-2 text-neutral-600">
                                {expandedSections['metadata'] ? '▼' : '▶'}
                            </span>
                            Metadata
                        </h3>
                    </div>
                    {expandedSections['metadata'] && (
                        <div className="p-4 bg-white">
                            <Field
                                label="Request ID"
                                value={manifest.core.request_id}
                                mono
                            />
                            <Field
                                label="Schema Version"
                                value={manifest.core.schema_version}
                                copyable={false}
                            />
                            <Field
                                label="Signature Profile"
                                value={manifest.core.signature_profile}
                                copyable={false}
                            />
                            <Field
                                label="Domain Separator"
                                value={manifest.core.domain_sep}
                                mono
                            />
                            <Field
                                label="Timestamp"
                                value={new Date(manifest.envelope.created_at).toISOString()}
                            />
                        </div>
                    )}
                </section>

                {/* File Information Section */}
                <section className="border border-neutral-200 rounded-md overflow-hidden">
                    <div
                        className="bg-neutral-100 px-4 py-3 cursor-pointer hover:bg-neutral-200 transition-colors focus:outline-none"
                        onClick={() => toggleSection('file_info')}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                toggleSection('file_info');
                            }
                        }}
                    >
                        <h3 className="text-base font-medium text-neutral-900">
                            <span className="mr-2 text-neutral-600">
                                {expandedSections['file_info'] ? '▼' : '▶'}
                            </span>
                            File Information
                        </h3>
                    </div>
                    {expandedSections['file_info'] && (
                        <div className="p-4 bg-white">
                            <Field
                                label="Hash"
                                value={manifest.core.hash}
                                mono
                            />
                            <Field
                                label="Hash Algorithm"
                                value={manifest.core.algorithm}
                            />
                            <Field
                                label="File Size"
                                value={`${manifest.core.size.toLocaleString()} bytes`}
                            />
                            <Field
                                label="Storage Bucket"
                                value={manifest.core.storage_bucket}
                            />
                            <Field
                                label="Object ID"
                                value={manifest.core.immutable_object_id}
                                mono
                            />
                        </div>
                    )}
                </section>

                {/* Signatures Section */}
                <section className="border border-neutral-200 rounded-md overflow-hidden">
                    <div
                        className="bg-neutral-100 px-4 py-3 cursor-pointer hover:bg-neutral-200 transition-colors focus:outline-none"
                        onClick={() => toggleSection('signatures')}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                toggleSection('signatures');
                            }
                        }}
                    >
                        <h3 className="text-base font-medium text-neutral-900">
                            <span className="mr-2 text-neutral-600">
                                {expandedSections['signatures'] ? '▼' : '▶'}
                            </span>
                            Cryptographic Signatures
                        </h3>
                    </div>
                    {expandedSections['signatures'] && (
                        <div className="p-4 bg-white space-y-6">
                            {Object.entries(manifest.signatures).map(([key, value]) => {
                                if (!value) return null;
                                
                                const prettyKey = key === 'fn_dsa' ? 'FN-DSA' : key === 'ml_dsa' ? 'ML-DSA' : key === 'slh_dsa' ? 'SLH-DSA' : key === 'hmac_sha256' ? 'HMAC-SHA256' : key === 'ecdsa_p256' ? 'ECDSA P256' : key.replace('_', ' ');

                                return (
                                    <div key={key} className="border-l-4 border-primary-600 pl-4">
                                        <h4 className="text-sm font-semibold text-neutral-900 mb-4 uppercase tracking-wider">
                                            {prettyKey} Signature
                                        </h4>
                                        <Field
                                            label="Signature (base64)"
                                            value={value as string}
                                            mono
                                        />
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </section>
            </div>

            {/* Full JSON View */}
            <details className="mt-4 px-6 pb-6">
                <summary className="cursor-pointer text-sm font-medium text-primary-600 hover:text-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 rounded px-2 py-1 inline-block">
                    View Full JSON Structure
                </summary>
                <pre className="mt-3 bg-neutral-50 p-4 rounded text-xs font-mono overflow-x-auto border border-neutral-200 max-h-96">
                    {JSON.stringify(manifest, null, 2)}
                </pre>
            </details>
        </div>
    );
};

export default ManifestViewer;

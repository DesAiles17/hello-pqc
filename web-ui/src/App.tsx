import { useState } from 'react';
import type { SignedManifest, FileMetadata, ProcessRequest } from './types';
import { Toaster } from 'react-hot-toast';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import AuthPage from './components/AuthPage';
import MainPage from './components/MainPage';
import FileUploadZone from './components/FileUploadZone';
import ManifestViewer from './components/ManifestViewer';
import VerifyPage from './components/VerifyPage';
import apiClient from './api/client';
import toast from 'react-hot-toast';
import { getSafeErrorMessage } from './api/errors';

function SignPage({ onBack }: { onBack: () => void }) {
  const [uploadedFilePath, setUploadedFilePath] = useState<string | null>(null);
  const [fileMetadata, setFileMetadata] = useState<FileMetadata | null>(null);
  const [signatureProfile, setSignatureProfile] = useState<'classical' | 'pqc' | 'hybrid'>('hybrid');
  const [classicalSig, setClassicalSig] = useState<string>('rsa_pss');
  const [pqcSig, setPqcSig] = useState<string>('ml_dsa');
  const [hashAlgorithm, setHashAlgorithm] = useState<'SHA256' | 'Keccak256' | 'BLAKE3'>('SHA256');
  const [signing, setSigning] = useState(false);
  const [manifest, setManifest] = useState<SignedManifest | null>(null);

  const normalizeManifest = (data: any): SignedManifest => {
    if (data?.core && data?.envelope) {
      return data as SignedManifest;
    }

    const legacy = data?.manifest ?? {};
    return {
      core: {
        schema_version: legacy.schema_version ?? 'pqc-hons.manifest.v1',
        domain_sep: legacy.domain_sep ?? 'pqc-hons.manifest.v1',
        signature_profile: legacy.signature_profile ?? 'hybrid',
        request_id: legacy.request_id ?? 'unknown',
        immutable_object_id: legacy.immutable_object_id ?? 'unknown',
        hash: legacy.hash ?? '',
        algorithm: legacy.algorithm ?? '',
        size: legacy.size ?? 0,
        storage_bucket: legacy.storage_bucket ?? 'unknown',
        storage_key: legacy.storage_key ?? 'unknown',
      },
      envelope: {
        created_at: legacy.timestamp ?? new Date().toISOString(),
        context: legacy.context ?? '',
        original_path: legacy.original_path ?? '',
      },
      signatures: {
        rsa_pss: data?.signatures?.rsa_pss ?? data?.rsa_signature?.signature,
        ml_dsa: data?.signatures?.ml_dsa ?? data?.ml_dsa_signature?.signature,
        eddsa: data?.signatures?.eddsa,
        ecdsa_p256: data?.signatures?.ecdsa_p256,
        hmac_sha256: data?.signatures?.hmac_sha256,
        slh_dsa: data?.signatures?.slh_dsa,
        fn_dsa: data?.signatures?.fn_dsa,
      },
    };
  };

  const handleFileUploaded = (filePath: string, metadata: FileMetadata) => {
    setUploadedFilePath(filePath);
    setFileMetadata(metadata);
    setManifest(null);
  };

  const handleSignFile = async () => {
    if (!uploadedFilePath) {
      toast.error('No file uploaded');
      return;
    }

    setSigning(true);
    const toastId = toast.loading('Signing file...');

    try {
      const profileStr = signatureProfile === 'classical' 
        ? classicalSig 
        : signatureProfile === 'pqc' 
          ? pqcSig 
          : `${classicalSig}_${pqcSig}`;

      const request: ProcessRequest = {
        file_path: uploadedFilePath,
        signature_profile: profileStr,
        hash_algorithm: hashAlgorithm,
        // domain_sep omitted - let server use its configured default (server-controlled for security)
        // schema_version omitted - let server use its configured default (server-controlled for security)
        bucket: 'pqc-objects',
      };

      const response = await apiClient.post('/process', request);
      setManifest(normalizeManifest(response.data.manifest));
      toast.success('File signed successfully!', { id: toastId });
    } catch (error: any) {
      const errorMsg = getSafeErrorMessage(error, 'Signing failed');
      toast.error(errorMsg, { id: toastId });
    } finally {
      setSigning(false);
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
          <h1 className="text-2xl font-semibold text-neutral-900">Sign File</h1>
        </div>
      </header>

      <main className="flex-1 max-w-screen-lg mx-auto px-8 py-8 w-full">
        {!manifest && (
          <div className="space-y-8">
            <div className="bg-white border border-neutral-200 rounded-md p-8">
              <h2 className="text-lg font-medium text-neutral-900 mb-6">Step 1: Upload File</h2>
              <FileUploadZone onFileUploaded={handleFileUploaded} />
              {fileMetadata && (
                <div className="mt-4 bg-success-100 border-l-4 border-success-600 px-4 py-3 rounded text-sm text-neutral-900">
                  <span className="font-medium">Uploaded:</span> {fileMetadata.originalName} ({(fileMetadata.size / 1024).toFixed(2)} KB)
                </div>
              )}
            </div>

            {uploadedFilePath && (
              <div className="bg-white border border-neutral-200 rounded-md p-8">
                <h2 className="text-lg font-medium text-neutral-900 mb-6">Step 2: Configure Signature</h2>

                <div className="mb-6">
                  <label htmlFor="profile" className="block text-sm font-medium text-neutral-900 mb-2">
                    Signature Profile
                  </label>
                  <select
                    id="profile"
                    value={signatureProfile}
                    onChange={(e) => setSignatureProfile(e.target.value as any)}
                    className="w-full px-3 py-2 border border-neutral-300 rounded-sm text-base focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                  >
                    <option value="classical">Classical</option>
                    <option value="pqc">Post-Quantum</option>
                    <option value="hybrid">Hybrid</option>
                  </select>
                </div>

                {signatureProfile !== 'pqc' && (
                  <div className="mb-6">
                    <label htmlFor="classicalSig" className="block text-sm font-medium text-neutral-900 mb-2">
                      Classical Signature
                    </label>
                    <select
                      id="classicalSig"
                      value={classicalSig}
                      onChange={(e) => setClassicalSig(e.target.value)}
                      className="w-full px-3 py-2 border border-neutral-300 rounded-sm text-base focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                    >
                      <option value="rsa_pss">RSA PSS</option>
                      <option value="eddsa">EdDSA</option>
                      <option value="ecdsa">ECDSA</option>
                      <option value="hmac_sha256">HMAC SHA-256</option>
                    </select>
                  </div>
                )}

                {signatureProfile !== 'classical' && (
                  <div className="mb-6">
                    <label htmlFor="pqcSig" className="block text-sm font-medium text-neutral-900 mb-2">
                      Post-Quantum Signature
                    </label>
                    <select
                      id="pqcSig"
                      value={pqcSig}
                      onChange={(e) => setPqcSig(e.target.value)}
                      className="w-full px-3 py-2 border border-neutral-300 rounded-sm text-base focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                    >
                      <option value="ml_dsa">ML-DSA</option>
                      <option value="slh_dsa">SLH-DSA</option>
                      <option value="fn_dsa">FN-DSA</option>
                    </select>
                  </div>
                )}

                <div className="mb-8">
                  <label htmlFor="algorithm" className="block text-sm font-medium text-neutral-900 mb-2">
                    Hash Algorithm
                  </label>
                  <select
                    id="algorithm"
                    value={hashAlgorithm}
                    onChange={(e) => setHashAlgorithm(e.target.value as any)}
                    className="w-full px-3 py-2 border border-neutral-300 rounded-sm text-base focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                  >
                    <option value="SHA256">SHA-256</option>
                    <option value="Keccak256">Keccak-256</option>
                    <option value="BLAKE3">BLAKE3</option>
                  </select>
                </div>

                <button
                  onClick={handleSignFile}
                  disabled={signing}
                  className="w-full bg-primary-600 text-white px-6 py-3 rounded-sm text-base font-medium hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {signing ? 'Signing File...' : 'Sign File'}
                </button>
              </div>
            )}
          </div>
        )}

        {manifest && (
          <div className="space-y-4">
            <ManifestViewer manifest={manifest} />
            <div className="flex gap-3">
              <button
                onClick={() => {
                  setManifest(null);
                  setUploadedFilePath(null);
                  setFileMetadata(null);
                }}
                className="bg-primary-600 text-white px-6 py-2.5 rounded-md text-sm font-medium hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 transition-colors"
              >
                Sign Another File
              </button>
              <button
                onClick={onBack}
                className="bg-neutral-600 text-white px-6 py-2.5 rounded-md text-sm font-medium hover:bg-neutral-700 focus:outline-none focus:ring-2 focus:ring-neutral-500 focus:ring-offset-2 transition-colors"
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

function SettingsPage({ onBack }: { onBack: () => void }) {
  const { clearAuth } = useAuth();

  const handleLogout = () => {
    clearAuth();
    onBack();
    toast.success('API key cleared');
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
          <h1 className="text-2xl font-semibold text-neutral-900">Settings</h1>
        </div>
      </header>

      <main className="flex-1 max-w-screen-lg mx-auto px-8 py-8 w-full">
        <div className="max-w-md space-y-8">
          {/* API Key Management */}
          <div className="bg-white border border-neutral-200 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-neutral-900 mb-4">API Key</h2>
            <p className="text-sm text-neutral-600 mb-4">
              Your API key is currently stored in this session.
            </p>
            <button
              onClick={handleLogout}
              className="w-full px-4 py-2.5 bg-error-600 text-white rounded-md text-sm font-medium hover:bg-error-700 transition-colors"
            >
              Change API Key
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}

function AppContent() {
  const { isAuthenticated } = useAuth();
  const [currentPage, setCurrentPage] = useState<'main' | 'sign' | 'verify' | 'settings'>('main');

  if (!isAuthenticated) {
    return <AuthPage onAuthenticated={() => setCurrentPage('main')} />;
  }

  return (
    <>
      {currentPage === 'main' && <MainPage onNavigate={setCurrentPage} />}
      {currentPage === 'sign' && <SignPage onBack={() => setCurrentPage('main')} />}
      {currentPage === 'verify' && <VerifyPage onBack={() => setCurrentPage('main')} />}
      {currentPage === 'settings' && <SettingsPage onBack={() => setCurrentPage('main')} />}
    </>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
      <Toaster position="top-right" />
    </AuthProvider>
  );
}

export default App;

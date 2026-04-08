// Type definitions for PQC File Signing System

export interface ManifestCore {
    schema_version: string;
    domain_sep: string;
    signature_profile: string;
    request_id: string;
    immutable_object_id: string;
    hash: string;
    algorithm: string;
    size: number;
    storage_bucket: string;
    storage_key: string;
}

export interface ManifestEnvelope {
    created_at: string;
    context: string;
    original_path: string;
    source_file_metadata?: SourceFileMetadata;
}

export interface SourceFileMetadata {
    created_at?: string;
    last_modified_at?: string;
    last_accessed_at?: string;
}

export interface Signatures {
    rsa_pss?: string;
    eddsa?: string;
    ecdsa_p256?: string;
    ml_dsa?: string;
    hmac_sha256?: string;
    slh_dsa?: string;
    fn_dsa?: string;
}

export interface SignedManifest {
    core: ManifestCore;
    envelope: ManifestEnvelope;
    signatures: Signatures;
}

export interface UploadResponse {
    file_path: string;
    original_filename: string;
    size: number;
    content_type: string;
    uploaded_at: string;
}

export interface ProcessRequest {
    file_path: string;
    signature_profile: string;
    hash_algorithm: 'SHA256' | 'Keccak256' | 'BLAKE3';
    domain_sep?: string;  // Optional - server will use default if not provided
    schema_version?: string;  // Optional - server will use default if not provided
    bucket: string;
}

export interface ProcessResponse {
    manifest: SignedManifest;
    request_id: string;
}

export interface VerificationCheck {
    name: string;
    passed: boolean;
    details: string;
}

export interface VerificationMetadata {
    signature_profile: string;
    hash_algorithm: string;
    canonical_manifest_hash: string;
    manifest_created_at: string;
    manifest_size: number;
    storage_bucket: string;
    storage_key: string;
}

export interface VerifyRequest {
    request_id: string;
    verify_object?: boolean;
    file_path?: string;  // Optional file path for file hash verification
    provided_hash?: string;  // Optional pre-computed hash
    provided_size?: number;
    provided_algorithm?: string;
    provided_immutable_object_id?: string;
    provided_storage_bucket?: string;
    provided_storage_key?: string;
}

export interface VerifyResponse {
    request_id: string;
    signature_ok: boolean;
    object_ok?: boolean;
    file_hash_match: boolean;  // True if provided file hash matches manifest hash
    overall_ok: boolean;
    errors: string[];
    checks?: VerificationCheck[];
    metadata?: VerificationMetadata;
}

export interface FileMetadata {
    originalName: string;
    size: number;
    mimeType: string;
    uploadedAt: string;
}

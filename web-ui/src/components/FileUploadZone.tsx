import { useCallback, useState } from 'react';
import type { UploadResponse, FileMetadata } from '../types';
import { useDropzone } from 'react-dropzone';
import apiClient from '../api/client';
import toast from 'react-hot-toast';
import { getSafeErrorMessage } from '../api/errors';

interface FileUploadZoneProps {
    onFileUploaded: (filePath: string, metadata: FileMetadata) => void;
    maxSizeMB?: number;
}

interface FileUploadState {
    file: File | null;
    uploading: boolean;
    uploadProgress: number;
    error: Error | null;
}

const FileUploadZone: React.FC<FileUploadZoneProps> = ({
    onFileUploaded,
    maxSizeMB = 100,
}) => {
    const [state, setState] = useState<FileUploadState>({
        file: null,
        uploading: false,
        uploadProgress: 0,
        error: null,
    });

    const { getRootProps, getInputProps, isDragActive } = useDropzone({
        onDrop: useCallback((acceptedFiles: File[]) => {
            if (acceptedFiles.length === 0) {
                toast.error('No files accepted');
                return;
            }

            const file = acceptedFiles[0];

            // Validate file size
            const maxBytes = maxSizeMB * 1024 * 1024;
            if (file.size > maxBytes) {
                const errorMsg = `File size ${(file.size / 1024 / 1024).toFixed(2)}MB exceeds limit of ${maxSizeMB}MB`;
                toast.error(errorMsg);
                return;
            }

            setState({
                file,
                uploading: false,
                uploadProgress: 0,
                error: null,
            });
        }, [maxSizeMB]),
        multiple: false,
        maxSize: maxSizeMB * 1024 * 1024,
        disabled: state.uploading,
    });

    const handleUpload = async () => {
        if (!state.file) {
            toast.error('No file selected');
            return;
        }

        setState((prev) => ({ ...prev, uploading: true, uploadProgress: 0, error: null }));

        const toastId = toast.loading('Uploading file...');

        try {
            const formData = new FormData();
            formData.append('file', state.file);

            const response = await apiClient.post<UploadResponse>('/upload', formData, {
                onUploadProgress: (progressEvent) => {
                    const progress = progressEvent.total
                        ? Math.round((progressEvent.loaded * 100) / progressEvent.total)
                        : 0;
                    setState((prev) => ({ ...prev, uploadProgress: progress }));
                },
            });

            const { file_path, original_filename, size, content_type, uploaded_at } = response.data;

            onFileUploaded(file_path, {
                originalName: original_filename,
                size,
                mimeType: content_type,
                uploadedAt: uploaded_at,
            });

            toast.success('File uploaded successfully', { id: toastId });

            // Reset state after success
            setState({
                file: null,
                uploading: false,
                uploadProgress: 0,
                error: null,
            });
        } catch (error) {
            const err = error instanceof Error ? error : new Error('Upload failed');
            setState((prev) => ({ ...prev, error: err, uploading: false }));
            toast.error(getSafeErrorMessage(error, 'Upload failed'), { id: toastId });
        }
    };

    return (
        <div>
            {/* Drag-drop area */}
            <div
                {...getRootProps()}
                className={`border-2 border-dashed rounded-md p-12 text-center cursor-pointer transition-colors ${isDragActive
                    ? 'border-primary-600 bg-primary-100'
                    : state.uploading
                        ? 'border-neutral-300 bg-neutral-100 opacity-50 cursor-not-allowed'
                        : 'border-neutral-300 bg-neutral-50 hover:border-primary-500 hover:bg-primary-100'
                    }`}
            >
                <input {...getInputProps()} />
                {isDragActive ? (
                    <p className="text-base text-neutral-900">Drop file here</p>
                ) : (
                    <div className="pointer-events-none">
                        <p className="text-lg font-medium text-neutral-900 mb-2">Drag and drop a file here</p>
                        <p className="text-sm text-neutral-600 my-4">or</p>
                        <button
                            type="button"
                            className="pointer-events-auto bg-neutral-100 text-neutral-900 border border-neutral-300 px-6 py-2.5 rounded-sm text-sm font-medium hover:bg-neutral-200 hover:border-neutral-400 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-colors"
                        >
                            Click to select
                        </button>
                        <p className="text-xs text-neutral-500 mt-4">Maximum file size: {maxSizeMB}MB</p>
                    </div>
                )}
            </div>

            {/* File selected, not yet uploaded */}
            {state.file && !state.uploading && (
                <div className="mt-4 bg-white border border-neutral-200 rounded-md p-6 flex justify-between items-center">
                    <div>
                        <p className="font-medium text-neutral-900 mb-1">{state.file.name}</p>
                        <p className="text-sm text-neutral-600">
                            {(state.file.size / 1024 / 1024).toFixed(2)} MB
                        </p>
                    </div>

                    <div className="flex gap-3">
                        <button
                            onClick={handleUpload}
                            className="bg-primary-600 text-white px-5 py-2 rounded-sm text-sm font-medium hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 transition-colors"
                        >
                            Upload
                        </button>
                        <button
                            onClick={() => setState((prev) => ({ ...prev, file: null }))}
                            className="bg-neutral-600 text-white px-5 py-2 rounded-sm text-sm font-medium hover:bg-neutral-700 focus:outline-none focus:ring-2 focus:ring-neutral-500 focus:ring-offset-2 transition-colors"
                        >
                            Cancel
                        </button>
                    </div>
                </div>
            )}

            {/* Upload in progress */}
            {state.uploading && (
                <div className="mt-4">
                    <div className="bg-neutral-200 h-2 rounded-full overflow-hidden">
                        <div
                            className="bg-primary-600 h-full transition-all duration-300"
                            style={{ width: `${state.uploadProgress}%` }}
                        />
                    </div>
                    <p className="text-center text-sm text-neutral-600 mt-2">{state.uploadProgress}% uploaded</p>
                </div>
            )}
        </div>
    );
};

export default FileUploadZone;

import React, { useState, useRef } from 'react';
import { encryptFile } from '../crypto/fileEncryption';
import { isAllowedFileType, isFileSizeValid } from '../utils/helpers';

/**
 * File Upload Component for Encrypted File Sharing
 * Handles client-side file encryption before upload
 */
const FileUpload = ({ onFileUploaded, sessionKey, disabled = false }) => {
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  const handleFileSelect = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setError('');
    
    // Validate file type
    if (!isAllowedFileType(file.type)) {
      setError('File type not allowed. Please select a valid file type.');
      return;
    }

    // Validate file size
    if (!isFileSizeValid(file.size)) {
      setError('File size too large. Maximum allowed size is 50MB.');
      return;
    }

    if (!sessionKey) {
      setError('No session key available. Please establish a secure connection first.');
      return;
    }

    try {
      setUploading(true);
      setProgress(0);

      // Read file as ArrayBuffer
      const fileBuffer = await file.arrayBuffer();
      
      // Update progress
      setProgress(25);

      // Encrypt file
      const encryptedFile = await encryptFile(fileBuffer, sessionKey);
      
      // Update progress
      setProgress(50);

      // Prepare upload data
      const uploadData = {
        filename: file.name,
        size: file.size,
        type: file.type,
        encryptedData: encryptedFile.encryptedData,
        iv: encryptedFile.iv,
        authTag: encryptedFile.authTag
      };

      // Update progress
      setProgress(75);

      // Call upload callback
      await onFileUploaded(uploadData);

      // Complete
      setProgress(100);
      
      // Reset form
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

    } catch (err) {
      console.error('File upload failed:', err);
      setError(`File upload failed: ${err.message}`);
    } finally {
      setUploading(false);
      setProgress(0);
    }
  };

  const triggerFileSelect = () => {
    if (disabled || uploading) return;
    fileInputRef.current?.click();
  };

  return (
    <div className="file-upload">
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileSelect}
        style={{ display: 'none' }}
        disabled={disabled || uploading}
      />
      
      <button
        className={`file-upload-btn ${disabled || uploading ? 'disabled' : ''}`}
        onClick={triggerFileSelect}
        disabled={disabled || uploading}
      >
        {uploading ? (
          <span>
            <i className="icon-upload"></i>
            Encrypting... {progress}%
          </span>
        ) : (
          <span>
            <i className="icon-paperclip"></i>
            Attach File
          </span>
        )}
      </button>

      {uploading && (
        <div className="upload-progress">
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          <span className="progress-text">{progress}%</span>
        </div>
      )}

      {error && (
        <div className="upload-error">
          <i className="icon-error"></i>
          {error}
        </div>
      )}
    </div>
  );
};

export default FileUpload;
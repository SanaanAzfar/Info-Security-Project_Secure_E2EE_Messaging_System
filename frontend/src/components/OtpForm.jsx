/**
 * OTP verification component for two-factor authentication
 */

import { useState } from 'react';
import './Auth.css';

export function OtpForm({ onVerifyOtp, onBackToLogin, isLoading, error, identifier }) {
  const [otp, setOtp] = useState('');
  const [formErrors, setFormErrors] = useState({});

  const handleInputChange = (e) => {
    const value = e.target.value.replace(/\D/g, ''); // Only allow digits
    setOtp(value);

    // Clear field error when user starts typing
    if (formErrors.otp) {
      setFormErrors(prev => ({
        ...prev,
        otp: ''
      }));
    }
  };

  const validateForm = () => {
    const errors = {};

    if (!otp) {
      errors.otp = 'OTP is required';
    } else if (otp.length !== 6) {
      errors.otp = 'OTP must be 6 digits';
    }

    return errors;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const errors = validateForm();
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    await onVerifyOtp(identifier, otp);
  };

  return (
    <div className="auth-container">
      <div className="auth-form">
        <div className="auth-header">
          <h2>Verify Your Identity</h2>
          <p>Enter the 6-digit code sent to your email</p>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="otp">One-Time Password</label>
            <input
              type="text"
              id="otp"
              name="otp"
              value={otp}
              onChange={handleInputChange}
              className={formErrors.otp ? 'error' : ''}
              disabled={isLoading}
              maxLength="6"
              placeholder="000000"
              autoComplete="one-time-code"
            />
            {formErrors.otp && <span className="error-message">{formErrors.otp}</span>}
          </div>

          {error && (
            <div className="error-banner">
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            className="auth-button primary"
            disabled={isLoading || otp.length !== 6}
          >
            {isLoading ? (
              <span>
                <span className="spinner"></span>
                Verifying...
              </span>
            ) : (
              'Verify OTP'
            )}
          </button>
        </form>

        <div className="auth-footer">
          <p>
            Didn't receive the code?{' '}
            <button
              type="button"
              className="link-button"
              onClick={onBackToLogin}
              disabled={isLoading}
            >
              Try Again
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}

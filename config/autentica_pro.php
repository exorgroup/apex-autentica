<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Configuration file for Autentica PRO settings including TOTP, session management, device limits, and backup codes
 * File Location: apex/autentica/config/autentica_pro.php
 */

return [

    /*
    |--------------------------------------------------------------------------
    | TOTP (Time-based One-Time Password) Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for TOTP authentication including algorithm, period, and
    | code length. SHA1 is used for maximum compatibility with authenticator apps.
    |
    */
    'totp' => [
        'algorithm' => env('AUTENTICA_TOTP_ALGORITHM', 'sha1'), // sha1 required for most authenticator apps
        'period' => env('AUTENTICA_TOTP_PERIOD', 30), // Time window in seconds
        'digits' => env('AUTENTICA_TOTP_DIGITS', 6), // Number of digits in TOTP code
        'window' => env('AUTENTICA_TOTP_WINDOW', 1), // Time windows to check (before/after current)
        'issuer' => env('AUTENTICA_TOTP_ISSUER', 'APEX Pro'), // Default issuer name for QR codes
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Management Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for advanced session management including concurrent session
    | limits and cleanup policies.
    |
    */
    'sessions' => [
        'max_concurrent' => env('AUTENTICA_MAX_CONCURRENT_SESSIONS', 5),
        'cleanup_hours' => env('AUTENTICA_SESSION_CLEANUP_HOURS', 24), // Hours of inactivity before cleanup
        'location_service' => env('AUTENTICA_LOCATION_SERVICE', 'ip-api'), // IP location service
        'location_timeout' => env('AUTENTICA_LOCATION_TIMEOUT', 5), // Timeout for location requests
    ],

    /*
    |--------------------------------------------------------------------------
    | Trusted Device Management Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for trusted device management including limits and
    | cleanup policies.
    |
    */
    'devices' => [
        'max_trusted_devices' => env('AUTENTICA_MAX_TRUSTED_DEVICES', 10),
        'cleanup_days' => env('AUTENTICA_DEVICE_CLEANUP_DAYS', 90), // Days of inactivity before cleanup
        'auto_trust_same_ip' => env('AUTENTICA_AUTO_TRUST_SAME_IP', false), // Auto-trust from same IP
    ],

    /*
    |--------------------------------------------------------------------------
    | MFA Backup Codes Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for MFA backup recovery codes including count, length, and
    | cleanup policies.
    |
    */
    'backup_codes' => [
        'default_count' => env('AUTENTICA_BACKUP_CODE_COUNT', 10),
        'code_length' => env('AUTENTICA_BACKUP_CODE_LENGTH', 8),
        'cleanup_days' => env('AUTENTICA_BACKUP_CODE_CLEANUP_DAYS', 90), // Days after use before cleanup
        'format_with_dash' => env('AUTENTICA_BACKUP_CODE_FORMAT_DASH', true), // Format as XXXX-XXXX
        'low_count_warning' => env('AUTENTICA_BACKUP_CODE_LOW_WARNING', 2), // Warn when this many left
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Token Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for authentication tokens including expiration times and
    | cleanup policies.
    |
    */
    'tokens' => [
        'remember_expires_hours' => env('AUTENTICA_REMEMBER_TOKEN_HOURS', 8760), // 1 year
        'api_expires_hours' => env('AUTENTICA_API_TOKEN_HOURS', 8760), // 1 year
        'session_expires_hours' => env('AUTENTICA_SESSION_TOKEN_HOURS', 24), // 1 day
        'cleanup_expired' => env('AUTENTICA_TOKEN_AUTO_CLEANUP', true), // Auto cleanup expired tokens
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Configuration
    |--------------------------------------------------------------------------
    |
    | General security settings for Autentica PRO.
    |
    */
    'security' => [
        'signature_algorithm' => env('AUTENTICA_SIGNATURE_ALGORITHM', 'sha512'), // For database signatures
        'encryption_key_rotation' => env('AUTENTICA_KEY_ROTATION_DAYS', 365), // Key rotation days
        'max_failed_attempts' => env('AUTENTICA_MAX_FAILED_ATTEMPTS', 5), // Max failed login attempts
        'lockout_duration_minutes' => env('AUTENTICA_LOCKOUT_DURATION', 30), // Account lockout duration
    ],

    /*
    |--------------------------------------------------------------------------
    | OAuth2 Social Authentication Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for OAuth2 social authentication providers.
    |
    */
    'oauth2' => [
        'enabled_providers' => env('AUTENTICA_OAUTH2_PROVIDERS', 'google,microsoft'), // Comma-separated
        'token_refresh_buffer_minutes' => env('AUTENTICA_OAUTH2_REFRESH_BUFFER', 30), // Refresh before expiry
        'auto_link_by_email' => env('AUTENTICA_OAUTH2_AUTO_LINK_EMAIL', true), // Auto-link by email match
    ],

    /*
    |--------------------------------------------------------------------------
    | Cleanup and Maintenance Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for automatic cleanup and maintenance tasks.
    |
    */
    'maintenance' => [
        'auto_cleanup_enabled' => env('AUTENTICA_AUTO_CLEANUP', true),
        'cleanup_schedule' => env('AUTENTICA_CLEANUP_SCHEDULE', 'daily'), // daily, weekly, monthly
        'keep_security_logs_days' => env('AUTENTICA_KEEP_SECURITY_LOGS', 365), // Security event retention
        'batch_cleanup_size' => env('AUTENTICA_CLEANUP_BATCH_SIZE', 1000), // Records per cleanup batch
    ],

    /*
    |--------------------------------------------------------------------------
    | Base32 Configuration
    |--------------------------------------------------------------------------
    |
    | RFC 4648 compliant Base32 alphabet for TOTP secrets.
    |
    */
    'base32' => [
        'alphabet' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', // RFC 4648 standard
        'secret_length' => env('AUTENTICA_TOTP_SECRET_LENGTH', 32), // Length of TOTP secrets
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Enhanced logging settings for Autentica PRO.
    |
    */
    'logging' => [
        'channel' => env('AUTENTICA_LOG_CHANNEL', 'autentica'), // Custom log channel
        'level' => env('AUTENTICA_LOG_LEVEL', 'info'), // Log level
        'include_request_data' => env('AUTENTICA_LOG_REQUEST_DATA', false), // Include request in logs
        'mask_sensitive_data' => env('AUTENTICA_LOG_MASK_SENSITIVE', true), // Mask passwords, tokens, etc.
    ],

];

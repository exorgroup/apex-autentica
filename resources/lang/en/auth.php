<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: English language translations for Autentica authentication messages.
 * URL: apex/autentica/resources/lang/en/auth.php
 */

return [
    /*
    |--------------------------------------------------------------------------
    | Autentica Authentication Language Lines
    |--------------------------------------------------------------------------
    |
    | The following language lines are used during authentication for various
    | messages that we need to display to the user.
    |
    */

    // Login messages
    'login_success' => 'Login successful.',
    'failed' => 'These credentials do not match our records.',
    'locked' => 'Account is locked. Please try again in :minutes minutes.',
    'error' => 'An error occurred. Please try again.',

    // Password messages
    'password_changed' => 'Password changed successfully.',
    'password_reset_success' => 'Password reset successfully.',
    'current_password_incorrect' => 'The current password is incorrect.',
    'password_used_recently' => 'This password has been used recently. Please choose a different password.',

    // Password validation
    'password_min_length' => 'Password must be at least :length characters.',
    'password_require_uppercase' => 'Password must contain at least one uppercase letter.',
    'password_require_lowercase' => 'Password must contain at least one lowercase letter.',
    'password_require_numbers' => 'Password must contain at least one number.',
    'password_require_special' => 'Password must contain at least one special character.',
    'password_contains_user_info' => 'Password must not contain your name or email.',
    'password_valid' => 'Password meets all requirements.',

    // Permission messages
    'permission_granted' => 'Permission granted successfully.',
    'permission_revoked' => 'Permission revoked successfully.',
    'permission_denied' => 'You do not have permission to perform this action.',

    // Group messages
    'group_joined' => 'Successfully joined group :group.',
    'group_left' => 'Successfully left group :group.',
    'group_not_found' => 'Group not found.',

    // Security messages
    'suspicious_activity' => 'Suspicious activity detected.',
    'session_expired' => 'Your session has expired. Please login again.',
    'account_disabled' => 'Your account has been disabled.',
];

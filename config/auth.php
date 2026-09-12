<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Core authentication configuration file for Autentica. Defines basic authentication settings,
 *              password policies, session management, and account security parameters.
 * URL: exorgroup/apex-autentica/config/auth.php
 */

return [

    /*
    |--------------------------------------------------------------------------
    | Password Policies
    |--------------------------------------------------------------------------
    |
    | Define password requirements for your application.
    |
    */

    'password_policies' => [
        'min_length' => env('AUTH_PASSWORD_MIN_LENGTH', 8),
        'require_uppercase' => env('AUTH_PASSWORD_REQUIRE_UPPERCASE', true),
        'require_lowercase' => env('AUTH_PASSWORD_REQUIRE_LOWERCASE', true),
        'require_numbers' => env('AUTH_PASSWORD_REQUIRE_NUMBERS', true),
        'require_special_chars' => env('AUTH_PASSWORD_REQUIRE_SPECIAL', false),
        'password_history_count' => env('AUTH_PASSWORD_HISTORY_COUNT', 5),
        'password_expiry_days' => env('AUTH_PASSWORD_EXPIRY_DAYS', 0), // 0 = never expires
    ],

    /*
    |--------------------------------------------------------------------------
    | Account Security
    |--------------------------------------------------------------------------
    |
    | Configure account security settings.
    |
    */

    'security' => [
        'max_login_attempts' => env('AUTH_MAX_LOGIN_ATTEMPTS', 5),
        'lockout_duration' => env('AUTH_LOCKOUT_DURATION', 15), // minutes
        'remember_me_duration' => env('AUTH_REMEMBER_ME_DURATION', 30), // days
        'session_lifetime' => env('SESSION_LIFETIME', 120), // minutes
        'session_expire_on_close' => env('SESSION_EXPIRE_ON_CLOSE', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | API Token Settings
    |--------------------------------------------------------------------------
    |
    | Configure API token settings.
    |
    */

    'api_tokens' => [
        'expiry_days' => env('AUTH_API_TOKEN_EXPIRY_DAYS', 365),
        'refresh_enabled' => env('AUTH_API_TOKEN_REFRESH_ENABLED', true),
        'refresh_before_days' => env('AUTH_API_TOKEN_REFRESH_BEFORE_DAYS', 30),
    ],

];

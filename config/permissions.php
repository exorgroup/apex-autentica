<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Permission system configuration file. Defines permission types, caching strategies,
 *              and default permission settings for the authorization system.
 * URL: apex/autentica/config/permissions.php
 */

return [
    /*
    |--------------------------------------------------------------------------
    | Permission Types
    |--------------------------------------------------------------------------
    |
    | Define the available permission types in the system.
    |
    */

    'types' => [
        'create' => 'can_create',
        'read' => 'can_read',
        'update' => 'can_update',
        'delete' => 'can_delete',
        'print' => 'can_print',
        'history' => 'can_history',
    ],

    /*
    |--------------------------------------------------------------------------
    | Resource Types
    |--------------------------------------------------------------------------
    |
    | Define the types of resources that can have permissions.
    |
    */

    'resource_types' => [
        'model',
        'function',
        'module',
    ],

    /*
    |--------------------------------------------------------------------------
    | Permission Caching
    |--------------------------------------------------------------------------
    |
    | Configure permission caching settings.
    |
    */

    'cache' => [
        'enabled' => env('PERMISSIONS_CACHE_ENABLED', true),
        'ttl' => env('PERMISSIONS_CACHE_TTL', 3600), // seconds
        'prefix' => 'autentica_permissions',
        'tag' => 'autentica_permissions',
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Permissions
    |--------------------------------------------------------------------------
    |
    | Define default permissions for new users/groups.
    |
    */

    'defaults' => [
        'user' => [
            // Resource identifier => permissions array
        ],
        'group' => [
            // Resource identifier => permissions array
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Permission Inheritance
    |--------------------------------------------------------------------------
    |
    | Configure how permissions are inherited.
    |
    */

    'inheritance' => [
        'user_overrides_group' => true,
        'most_permissive_wins' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Permissions
    |--------------------------------------------------------------------------
    |
    | Configure custom permission handling.
    |
    */

    'custom' => [
        'separator' => ',',
        'max_length' => 255,
    ],
];

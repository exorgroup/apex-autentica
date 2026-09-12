<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Tenancy detection override. Merged as autentica.tenancy.
 * URL: exorgroup/apex-autentica/config/tenancy.php
 */

return [

    /*
    |--------------------------------------------------------------------------
    | Tenancy Mode
    |--------------------------------------------------------------------------
    |
    | Controls where migrations are published and how Autentica treats the
    | application's architecture.
    |
    |   'auto'  Detect: a database/migrations/tenant folder, or Stancl Tenancy
    |           being installed, means multi-tenant. Otherwise single-tenant.
    |   true    Force multi-tenant.
    |   false   Force single-tenant.
    |
    | Read from the environment so it survives config caching.
    |
    */

    'enabled' => env('AUTENTICA_TENANCY_ENABLED', 'auto'),

];

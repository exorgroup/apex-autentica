<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Resolves the host application's user model so the package never hard-codes
 *              App\Models\User and can be installed into any Laravel application.
 * URL: exorgroup/apex-autentica/src/Core/Support/Autentica.php
 */

namespace Apex\Autentica\Core\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Log;

class Autentica
{
    /**
     * Get the host application's user model class name.
     *
     * Read from Laravel's own auth config, which every application already sets, so there is
     * nothing extra to configure in the common case. Type hints throughout the package use
     * Illuminate\Foundation\Auth\User (the base class every user model extends); this resolver
     * is for the places that need the concrete class — relations and queries.
     *
     * @return class-string
     */
    public static function userModel(): string
    {
        try {
            $model = config('auth.providers.users.model');

            return is_string($model) && $model !== '' ? $model : 'App\\Models\\User';
        } catch (\Exception $e) {
            Log::error('Autentica.php - userModel() method error: ' . $e->getMessage());

            return 'App\\Models\\User';
        }
    }

    /**
     * Start a query against the host application's user model.
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public static function users(): Builder
    {
        try {
            $model = static::userModel();

            return $model::query();
        } catch (\Exception $e) {
            Log::error('Autentica.php - users() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * The value Eloquent stores in a polymorphic *_type column for a given class.
     *
     * Eloquent writes getMorphClass(), which is the alias when the application has configured
     * Relation::morphMap() and the fully-qualified class name otherwise. Any hand-written
     * comparison against a *_type column must resolve the same way or it silently matches
     * nothing. Resolved from the map directly, so no model is instantiated.
     *
     * @param string $class
     * @return string
     */
    public static function morphClass(string $class): string
    {
        try {
            $map = Relation::morphMap();

            if (! empty($map)) {
                $alias = array_search($class, $map, true);

                if ($alias !== false) {
                    return (string) $alias;
                }
            }

            return $class;
        } catch (\Exception $e) {
            Log::error('Autentica.php - morphClass() method error: ' . $e->getMessage());

            return $class;
        }
    }

    /**
     * The value stored in a polymorphic *_type column for the host application's user model.
     *
     * @return string
     */
    public static function userMorphClass(): string
    {
        return static::morphClass(static::userModel());
    }

    /**
     * Detect whether the host application uses a multi-tenant architecture.
     *
     * Priority: explicit config, then a tenant migrations folder, then the presence of Stancl
     * Tenancy, then single-tenant as the safe default.
     *
     * @return bool
     */
    public static function isMultiTenant(): bool
    {
        try {
            $enabled = config('autentica.tenancy.enabled', 'auto');
            if ($enabled !== 'auto') {
                return (bool) $enabled;
            }

            if (is_dir(database_path('migrations/tenant'))) {
                return true;
            }

            return class_exists('\Stancl\Tenancy\TenancyServiceProvider');
        } catch (\Exception $e) {
            Log::warning('Autentica.php - isMultiTenant() failed, defaulting to single-tenant: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Where this application's migrations should be published.
     *
     * Both the Core and Pro providers publish to the same place, so the decision lives here
     * rather than being duplicated in each.
     *
     * @return string
     */
    public static function migrationPath(): string
    {
        return static::isMultiTenant()
            ? database_path('migrations/tenant')
            : database_path('migrations');
    }
}

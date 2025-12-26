<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Service provider for registering Autentica services, commands, and configurations
 *              in the Laravel application container.
 * URL: apex/autentica/src/AutenticaServiceProvider.php
 */

namespace Apex\Autentica;

use Illuminate\Support\ServiceProvider;
use Apex\Autentica\Core\Console\TestAutenticaCommand;
use Apex\Autentica\Core\Services\AuthenticationService;
use Apex\Autentica\Core\Services\AuthorizationService;
use Apex\Autentica\Core\Services\PermissionCache;

class AutenticaServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register(): void
    {
        // Register configuration
        $this->mergeConfigFrom(
            __DIR__ . '/../config/auth.php',
            'autentica.auth'
        );

        $this->mergeConfigFrom(
            __DIR__ . '/../config/permissions.php',
            'autentica.permissions'
        );

        // Register services as singletons
        $this->app->singleton(AuthenticationService::class, function ($app) {
            return new AuthenticationService();
        });

        $this->app->singleton(AuthorizationService::class, function ($app) {
            return new AuthorizationService();
        });

        $this->app->singleton(PermissionCache::class, function ($app) {
            return new PermissionCache();
        });

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                TestAutenticaCommand::class,
            ]);
        }
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot(): void
    {
        // Load translations
        $this->loadTranslationsFrom(__DIR__ . '/../resources/lang', 'autentica');

        // Publish configuration
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/auth.php' => config_path('autentica/auth.php'),
                __DIR__ . '/../config/permissions.php' => config_path('autentica/permissions.php'),
            ], 'autentica-config');

            // Smart migration publishing based on architecture detection
            $isMultiTenant = $this->detectMultiTenancy();
            $migrationPath = $isMultiTenant 
                ? database_path('migrations/tenant')
                : database_path('migrations');

            $this->publishes([
                __DIR__ . '/../database/tenant/migrations' => $migrationPath,
            ], 'autentica-migrations');

            // Publish language files
            $this->publishes([
                __DIR__ . '/../resources/lang' => resource_path('lang/vendor/autentica'),
            ], 'autentica-lang');
        }
    }

    /**
     * Detect if the application uses multi-tenancy architecture.
     *
     * @return bool
     */
    protected function detectMultiTenancy(): bool
    {
        try {
            // 1. Explicit configuration wins (most reliable)
            $enabled = config('autentica.tenancy.enabled', 'auto');
            if ($enabled !== 'auto') {
                return (bool) $enabled;
            }

            // 2. Check for tenant migrations folder (very reliable)
            if (is_dir(database_path('migrations/tenant'))) {
                return true;
            }

            // 3. Check for Stancl Tenancy package (reliable)
            if (class_exists('\Stancl\Tenancy\TenancyServiceProvider')) {
                return true;
            }

            // 4. Default to single-tenant (fallback)
            return false;

        } catch (\Exception $e) {
            // Log warning and default to safe option
            \Illuminate\Support\Facades\Log::warning('APEX Autentica: Could not detect tenancy mode, defaulting to single-tenant', [
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides(): array
    {
        return [
            AuthenticationService::class,
            AuthorizationService::class,
            PermissionCache::class,
        ];
    }
}

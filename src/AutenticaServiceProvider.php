<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Service provider for registering Autentica services, commands, and configurations
 *              in the Laravel application container.
 * URL: exorgroup/apex-autentica/src/AutenticaServiceProvider.php
 */

namespace Apex\Autentica;

use Illuminate\Support\ServiceProvider;
use Apex\Autentica\Core\Console\DoctorCommand;
use Apex\Autentica\Core\Console\TestAutenticaCommand;
use Apex\Autentica\Core\Services\AuthenticationService;
use Apex\Autentica\Core\Services\AuthorizationService;
use Apex\Autentica\Core\Services\PermissionCache;
use Apex\Autentica\Core\Support\Autentica;

class AutenticaServiceProvider extends ServiceProvider
{
    /**
     * The Pro provider, referenced by name only.
     *
     * Core must never import or type-hint anything under src/Pro — Pro is separately licensed
     * and will eventually ship as its own package. Naming it as a string keeps Core compiling
     * and running with src/Pro absent, and makes that future split a directory move.
     */
    protected const PRO_PROVIDER = 'Apex\\Autentica\\Pro\\AutenticaProServiceProvider';

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

        $this->mergeConfigFrom(
            __DIR__ . '/../config/tenancy.php',
            'autentica.tenancy'
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
                DoctorCommand::class,
                TestAutenticaCommand::class,
            ]);
        }

        // Hand over to Pro if it is installed. Core works exactly the same without it.
        if (class_exists(static::PRO_PROVIDER)) {
            $this->app->register(static::PRO_PROVIDER);
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
                __DIR__ . '/../config/tenancy.php' => config_path('autentica/tenancy.php'),
            ], 'autentica-config');

            // Core migrations only. Pro publishes its own under the autentica-pro-migrations
            // tag, so a Core-only installation never creates commercially licensed tables.
            $this->publishes([
                __DIR__ . '/../database/tenant/migrations/core' => Autentica::migrationPath(),
            ], 'autentica-migrations');

            // Publish language files
            $this->publishes([
                __DIR__ . '/../resources/lang' => resource_path('lang/vendor/autentica'),
            ], 'autentica-lang');
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

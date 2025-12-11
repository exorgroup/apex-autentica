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

            // Publish migrations
            $this->publishes([
                __DIR__ . '/../database/tenant/migrations' => database_path('migrations/tenant'),
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

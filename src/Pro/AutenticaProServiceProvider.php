<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Registers Autentica Pro services, configuration and migrations. Kept separate
 *              from the Core provider so src/Pro can become its own package unchanged.
 * File Location: exorgroup/apex-autentica/src/Pro/AutenticaProServiceProvider.php
 */

namespace Apex\Autentica\Pro;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Apex\Autentica\Core\Support\Autentica;
use Apex\Autentica\Pro\Console\CleanupCommand;
use Apex\Autentica\Pro\Listeners\AuthEventSubscriber;
use Apex\Autentica\Pro\Services\AuthTokenService;
use Apex\Autentica\Pro\Services\DeviceManagementService;
use Apex\Autentica\Pro\Services\MfaBackupService;
use Apex\Autentica\Pro\Services\MfaService;
use Apex\Autentica\Pro\Services\OAuth2Service;
use Apex\Autentica\Pro\Services\SessionManager;
use Apex\Autentica\Pro\Services\TOTPService;
use Apex\Autentica\Pro\Support\LicenceGate;

/**
 * Pro depends on Core; Core never depends on Pro. The Core provider registers this one behind
 * a class_exists() check, so an installation without src/Pro simply never sees it.
 */
class AutenticaProServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register(): void
    {
        // Pro services read config('autentica_pro.*'); without this merge every setting would
        // silently fall back to its hard-coded default.
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/autentica_pro.php',
            'autentica_pro'
        );

        if (! LicenceGate::allows()) {
            return;
        }

        foreach ([
            AuthTokenService::class,
            DeviceManagementService::class,
            MfaBackupService::class,
            MfaService::class,
            OAuth2Service::class,
            SessionManager::class,
            TOTPService::class,
        ] as $service) {
            // No closure: the container resolves constructor dependencies itself, which
            // matters for services that compose others (MfaService takes TOTPService and
            // MfaBackupService). A hand-rolled `new` would fail on those.
            $this->app->singleton($service);
        }
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot(): void
    {
        // Registered before the console guard below: the audit trail has to cover artisan and
        // queued work too, not only web requests.
        if (LicenceGate::allows()) {
            Event::subscribe(AuthEventSubscriber::class);
        }

        if (! $this->app->runningInConsole()) {
            return;
        }

        // Must publish to config/autentica_pro.php, NOT config/autentica/pro.php: Laravel maps
        // a nested config directory to a dotted key, so the latter would load as
        // config('autentica.pro') while every Pro service reads config('autentica_pro.*').
        $this->publishes([
            __DIR__ . '/../../config/autentica_pro.php' => config_path('autentica_pro.php'),
        ], 'autentica-pro-config');

        // Published under their own tag so a Core-only installation never creates Pro tables.
        $this->publishes([
            __DIR__ . '/../../database/tenant/migrations/pro' => Autentica::migrationPath(),
        ], 'autentica-pro-migrations');

        $this->commands([
            CleanupCommand::class,
        ]);
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides(): array
    {
        return [
            AuthTokenService::class,
            DeviceManagementService::class,
            MfaBackupService::class,
            MfaService::class,
            OAuth2Service::class,
            SessionManager::class,
            TOTPService::class,
        ];
    }
}

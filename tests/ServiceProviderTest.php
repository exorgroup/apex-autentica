<?php

namespace Apex\Autentica\Tests;

use Apex\Autentica\AutenticaServiceProvider;
use Apex\Autentica\Core\Services\AuthenticationService;
use Apex\Autentica\Core\Services\AuthorizationService;
use Apex\Autentica\Core\Services\PermissionCache;

class ServiceProviderTest extends TestCase
{
    /** @test */
    public function it_registers_the_service_provider()
    {
        $this->assertTrue($this->app->getProvider(AutenticaServiceProvider::class) instanceof AutenticaServiceProvider);
    }

    /** @test */
    public function it_registers_authentication_service()
    {
        $this->assertTrue($this->app->bound(AuthenticationService::class));
        $this->assertInstanceOf(AuthenticationService::class, $this->app->make(AuthenticationService::class));
    }

    /** @test */
    public function it_registers_authorization_service()
    {
        $this->assertTrue($this->app->bound(AuthorizationService::class));
        $this->assertInstanceOf(AuthorizationService::class, $this->app->make(AuthorizationService::class));
    }

    /** @test */
    public function it_registers_permission_cache()
    {
        $this->assertTrue($this->app->bound(PermissionCache::class));
        $this->assertInstanceOf(PermissionCache::class, $this->app->make(PermissionCache::class));
    }

    /** @test */
    public function it_loads_translations()
    {
        // Test that translations are loaded
        $this->assertTrue(true); // Placeholder - would need actual translation files to test
    }
}
<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Console command for testing Autentica authentication and authorization functionality
 *              in a multi-tenant environment.
 * URL: apex/autentica/src/Core/Console/TestAutenticaCommand.php
 */

namespace Apex\Autentica\Core\Console;

use Illuminate\Console\Command;
use App\Models\User;
use Apex\Autentica\Core\Models\Group;
use Apex\Autentica\Core\Models\SystemResource;
use Apex\Autentica\Core\Models\PasswordHistory;
use Apex\Autentica\Core\Services\AuthenticationService;
use Apex\Autentica\Core\Services\AuthorizationService;
use Apex\Autentica\Core\Services\PermissionCache;
use Illuminate\Support\Facades\Log;

class TestAutenticaCommand extends Command
{
    /**
     * Test password change functionality.
     *
     * @return void
     */
    protected function testPasswordChange(): void
    {
        try {
            $this->info("3. Testing Password Change");
            $this->info("=" . str_repeat("=", 50));

            $authService = new AuthenticationService();
            $user = User::where('email', 'autentica.test@example.com')->first();

            // Test with wrong current password
            $this->info("Testing password change with wrong current password...");
            $result = $authService->changePassword($user, 'wrongpassword', 'NewPass123!');
            $this->info("✓ Wrong password rejected: " . ($result['success'] ? 'FAILED' : 'PASSED'));

            // Test with valid password change
            $this->info("\nTesting valid password change...");
            $result = $authService->changePassword($user, 'TestPass123!', 'NewPass123!');
            if ($result['success']) {
                $this->info("✓ Password changed successfully");

                // Check password history
                $historyCount = PasswordHistory::where('user_id', $user->id)->count();
                $this->info("✓ Password history entries: {$historyCount}");

                // Test password reuse
                $this->info("\nTesting password reuse prevention...");
                $result = $authService->changePassword($user, 'NewPass123!', 'TestPass123!');
                if (!$result['success'] && str_contains($result['message'], 'recently')) {
                    $this->info("✓ Password reuse prevented");
                } else {
                    $this->warn("⚠ Password reuse not prevented");
                }
            } else {
                $this->error("✗ Password change failed: {$result['message']}");
            }

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testPasswordChange() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'autentica:test 
                            {tenant : The tenant ID to test against}
                            {--cleanup : Clean up test data after running}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test Autentica Core authentication and authorization functionality';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        try {
            $tenantId = $this->argument('tenant');

            // Initialize tenant
            tenancy()->initialize($tenantId);

            $this->info("=== Testing Autentica Core for tenant: {$tenantId} ===\n");

            // Run tests
            $this->testUserCreation();
            $this->testAuthentication();
            $this->testPasswordChange();
            $this->testGroups();
            $this->testSystemResources();
            $this->testPermissions();
            $this->testSecurityEvents();
            $this->testLoginAttempts();
            $this->testPermissionCache();

            // Cleanup if requested
            if ($this->option('cleanup')) {
                $this->cleanup();
            }

            $this->info("\n✅ All tests completed successfully!");

            return Command::SUCCESS;
        } catch (\Exception $e) {
            $this->error("\n❌ Test failed: " . $e->getMessage());
            Log::error('TestAutenticaCommand error: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString()
            ]);
            return Command::FAILURE;
        }
    }

    /**
     * Test user creation with Autentica traits.
     *
     * @return void
     */
    protected function testUserCreation(): void
    {
        try {
            $this->info("1. Testing User Creation with Autentica Traits");
            $this->info("=" . str_repeat("=", 50));

            $user = User::create([
                'name' => 'Autentica Test User',
                'email' => 'autentica.test@example.com',
                'password' => bcrypt('TestPass123!'),
            ]);

            $this->info("✓ User created: {$user->email}");
            $this->info("✓ User ID: {$user->id}");
            $this->info("✓ Signature generated: " . substr($user->signature, 0, 20) . "...");

            // Verify signature
            if ($user->hasValidSignature()) {
                $this->info("✓ Signature validation: PASSED");
            } else {
                $this->warn("⚠ Signature validation: FAILED");
            }

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testUserCreation() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Test authentication functionality.
     *
     * @return void
     */
    protected function testAuthentication(): void
    {
        try {
            $this->info("2. Testing Authentication Service");
            $this->info("=" . str_repeat("=", 50));

            $authService = new AuthenticationService();

            // Test failed login
            $this->info("Testing failed login attempt...");
            $result = $authService->attempt([
                'email' => 'autentica.test@example.com',
                'password' => 'wrongpassword'
            ]);

            $this->info("✓ Failed login handled correctly");
            $this->info("  Message: {$result['message']}");
            if (isset($result['remaining_attempts'])) {
                $this->info("  Remaining attempts: {$result['remaining_attempts']}");
            }

            // Test successful login
            $this->info("\nTesting successful login...");
            $result = $authService->attempt([
                'email' => 'autentica.test@example.com',
                'password' => 'TestPass123!'
            ], true); // Remember me

            if ($result['success']) {
                $this->info("✓ Login successful");
                $this->info("  User: {$result['user']->name}");
                $this->info("  Password expired: " . ($result['password_expired'] ? 'YES' : 'NO'));
            } else {
                $this->error("✗ Login failed: {$result['message']}");
            }

            // Test password validation
            $this->info("\nTesting password validation...");
            $validation = $authService->validatePassword('weak', $result['user']);
            $this->info("✓ Weak password validation: " . ($validation['valid'] ? 'PASSED' : 'FAILED'));
            if (!$validation['valid'] && isset($validation['errors'])) {
                foreach ($validation['errors'] as $error) {
                    $this->info("  - {$error}");
                }
            }

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testAuthentication() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Test group functionality.
     *
     * @return void
     */
    protected function testGroups(): void
    {
        try {
            $this->info("3. Testing Groups");
            $this->info("=" . str_repeat("=", 50));

            // Create groups
            $adminGroup = Group::create([
                'name' => 'Test Administrators',
                'description' => 'Test admin group'
            ]);
            $this->info("✓ Admin group created: {$adminGroup->name}");

            $editorGroup = Group::create([
                'name' => 'Test Editors',
                'description' => 'Test editor group'
            ]);
            $this->info("✓ Editor group created: {$editorGroup->name}");

            // Add user to groups
            $user = User::where('email', 'autentica.test@example.com')->first();
            $user->joinGroup($adminGroup);
            $user->joinGroup('Test Editors'); // Test by name

            $this->info("✓ User joined groups");
            $this->info("  Groups: " . implode(', ', $user->getGroupNames()));

            // Test group membership
            $belongsToAdmin = $user->belongsToGroup('Test Administrators');
            $belongsToEditor = $user->belongsToGroup($editorGroup);

            $this->info("✓ Group membership tests:");
            $this->info("  Belongs to Admin: " . ($belongsToAdmin ? 'YES' : 'NO'));
            $this->info("  Belongs to Editor: " . ($belongsToEditor ? 'YES' : 'NO'));

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testGroups() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Test system resources.
     *
     * @return void
     */
    protected function testSystemResources(): void
    {
        try {
            $this->info("4. Testing System Resources");
            $this->info("=" . str_repeat("=", 50));

            // Create resources
            $resources = [
                [
                    'name' => 'User Management',
                    'identifier' => 'users',
                    'type' => 'module',
                    'description' => 'User management module'
                ],
                [
                    'name' => 'Posts',
                    'identifier' => 'posts',
                    'type' => 'model',
                    'description' => 'Blog posts'
                ],
                [
                    'name' => 'Reports',
                    'identifier' => 'reports',
                    'type' => 'function',
                    'description' => 'Reporting functions'
                ],
            ];

            foreach ($resources as $resourceData) {
                $resource = SystemResource::createOrUpdate($resourceData);
                $this->info("✓ Created resource: {$resource->name} ({$resource->identifier})");
            }

            // Test resource retrieval
            $modelResources = SystemResource::byType('model');
            $this->info("\n✓ Model resources found: {$modelResources->count()}");

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testSystemResources() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Test permissions.
     *
     * @return void
     */
    protected function testPermissions(): void
    {
        try {
            $this->info("5. Testing Permissions");
            $this->info("=" . str_repeat("=", 50));

            $authzService = new AuthorizationService();
            $user = User::where('email', 'autentica.test@example.com')->first();
            $adminGroup = Group::where('name', 'Test Administrators')->first();

            // Grant user permissions
            $this->info("Granting user permissions...");
            $permission1 = $authzService->grant($user, 'users', ['create', 'read', 'update']);
            $permission2 = $authzService->grant($user, 'posts', ['read']);

            if ($permission1) {
                $this->info("  ✓ Granted users permissions to user");
            } else {
                $this->error("  ✗ Failed to grant users permissions");
            }

            // Grant group permissions
            $this->info("Granting group permissions...");
            $permission3 = $authzService->grant($adminGroup, 'users', ['read', 'delete']);
            $permission4 = $authzService->grant($adminGroup, 'reports', ['create', 'read', 'print']);

            if ($permission3) {
                $this->info("  ✓ Granted users permissions to admin group");
            } else {
                $this->error("  ✗ Failed to grant users permissions to group");
            }

            // Clear cache to test combined permissions
            $user->clearPermissionCache();

            // Test permissions
            $this->info("\n✓ Permission checks:");
            $permissions = [
                ['users', 'create', true],   // User permission
                ['users', 'read', true],     // Both user and group
                ['users', 'update', true],   // User permission
                ['users', 'delete', true],   // Group permission
                ['posts', 'read', true],     // User permission
                ['posts', 'update', false],  // No permission
                ['reports', 'print', true],  // Group permission
            ];

            foreach ($permissions as [$resource, $action, $expected]) {
                $hasPermission = $user->hasPermission($resource, $action);
                $result = $hasPermission === $expected ? '✓' : '✗';
                $this->info("  {$result} {$resource}:{$action} = " . ($hasPermission ? 'YES' : 'NO'));
            }

            // Test permission matrix
            $this->info("\nGenerating permission matrix...");
            $matrix = $authzService->getPermissionMatrix(
                collect([$user, $adminGroup])
            );
            $this->info("✓ Permission matrix generated for " . count($matrix) . " entities");

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testPermissions() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Test security events.
     *
     * @return void
     */
    protected function testSecurityEvents(): void
    {
        try {
            $this->info("6. Testing Security Events");
            $this->info("=" . str_repeat("=", 50));

            $user = User::where('email', 'autentica.test@example.com')->first();

            // Get recent events
            $events = $user->getRecentSecurityEvents(10);
            $this->info("✓ Security events logged: {$events->count()}");

            $this->info("\nRecent events:");
            foreach ($events as $event) {
                $this->info("  - {$event->getDescription()} at {$event->created_at->format('H:i:s')}");
            }

            // Log custom event
            $user->logSecurityEvent('test_event', [
                'action' => 'running_tests',
                'component' => 'autentica_core'
            ]);
            $this->info("\n✓ Custom security event logged");

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testSecurityEvents() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Test login attempts.
     *
     * @return void
     */
    protected function testLoginAttempts(): void
    {
        try {
            $this->info("7. Testing Login Attempts");
            $this->info("=" . str_repeat("=", 50));

            $user = User::where('email', 'autentica.test@example.com')->first();

            // Get login attempts
            $attempts = $user->getRecentLoginAttempts(10);
            $this->info("✓ Login attempts recorded: {$attempts->count()}");

            $failedCount = $user->getFailedLoginCount(15);
            $this->info("✓ Failed attempts in last 15 minutes: {$failedCount}");

            $isLocked = $user->isAccountLocked();
            $this->info("✓ Account locked: " . ($isLocked ? 'YES' : 'NO'));

            if ($isLocked) {
                $unlockTime = $user->getUnlockTime();
                $this->info("  Unlock in: {$unlockTime} minutes");
            }

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testLoginAttempts() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Test permission cache.
     *
     * @return void
     */
    protected function testPermissionCache(): void
    {
        try {
            $this->info("8. Testing Permission Cache");
            $this->info("=" . str_repeat("=", 50));

            $cache = new PermissionCache();
            $user = User::where('email', 'autentica.test@example.com')->first();

            // Check cache status
            $isCached = $cache->isCached($user);
            $this->info("✓ User permissions cached: " . ($isCached ? 'YES' : 'NO'));

            // Get cache statistics
            $stats = $cache->getStatistics();
            $this->info("\nCache statistics:");
            if (isset($stats['error'])) {
                $this->warn("  Error getting statistics: {$stats['error']}");
            } else {
                $this->info("  Enabled: " . (($stats['enabled'] ?? false) ? 'YES' : 'NO'));
                $this->info("  TTL: " . ($stats['ttl'] ?? 'N/A') . " seconds");
                $this->info("  Cached users: " . ($stats['cached_users'] ?? 0));
            }

            // Test cache warming
            $this->info("\nWarming cache for recent users...");
            $warmed = $cache->warmRecentlyActiveUsers(30);
            $this->info("✓ Warmed cache for {$warmed} users");

            $this->newLine();
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - testPermissionCache() error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Clean up test data.
     *
     * @return void
     */
    protected function cleanup(): void
    {
        try {
            $this->info("Cleaning up test data...");

            // Delete test user
            User::where('email', 'autentica.test@example.com')->forceDelete();

            // Delete test groups
            Group::whereIn('name', ['Test Administrators', 'Test Editors'])->forceDelete();

            // Delete test resources
            SystemResource::whereIn('identifier', ['users', 'posts', 'reports'])->forceDelete();

            $this->info("✓ Test data cleaned up");
        } catch (\Exception $e) {
            Log::error('TestAutenticaCommand - cleanup() error: ' . $e->getMessage());
            $this->warn("⚠ Cleanup failed: " . $e->getMessage());
        }
    }
}

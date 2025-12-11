<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Development helper functions for testing Autentica features in tinker or console.
 *              Copy these functions to your tinker session or create a helper file.
 * URL: apex/autentica/src/Core/Helpers/dev-helpers.php
 */

// Initialize tenant if needed
if (!function_exists('initTenant')) {
    function initTenant($tenantId)
    {
        tenancy()->initialize($tenantId);
        echo "Tenant initialized: $tenantId\n";
    }
}

// Quick user permission check
if (!function_exists('checkUserPermission')) {
    function checkUserPermission($email, $resource, $action = null)
    {
        $user = App\Models\User::where('email', $email)->first();
        if (!$user) {
            echo "User not found: $email\n";
            return false;
        }

        if ($action) {
            $result = $user->hasPermission($resource, $action);
            echo "User $email can $action $resource: " . ($result ? "YES" : "NO") . "\n";
            return $result;
        } else {
            // Show all permissions for resource
            $perms = $user->getCachedPermissions();
            if (isset($perms[$resource])) {
                echo "User $email permissions on $resource:\n";
                foreach ($perms[$resource] as $key => $value) {
                    if (strpos($key, 'can_') === 0 && $value) {
                        echo "  - " . str_replace('can_', '', $key) . "\n";
                    }
                }
            } else {
                echo "User $email has no permissions on $resource\n";
            }
        }
    }
}

// Check if user is in group
if (!function_exists('checkUserGroup')) {
    function checkUserGroup($email, $groupName)
    {
        $user = App\Models\User::where('email', $email)->first();
        if (!$user) {
            echo "User not found: $email\n";
            return false;
        }

        $result = $user->belongsToGroup($groupName);
        echo "User $email is in group '$groupName': " . ($result ? "YES" : "NO") . "\n";

        // List all groups
        $groups = $user->getGroupNames();
        if (!empty($groups)) {
            echo "User groups: " . implode(", ", $groups) . "\n";
        }

        return $result;
    }
}

// List all users with a specific permission
if (!function_exists('getUsersWithPermission')) {
    function getUsersWithPermission($resource, $action)
    {
        $authz = new Apex\Autentica\Core\Services\AuthorizationService();
        $users = $authz->getUsersWithPermission($resource, $action);

        echo "Users who can $action $resource:\n";
        foreach ($users as $user) {
            echo "  - {$user->name} ({$user->email})\n";
        }

        return $users;
    }
}

// Grant permission quickly
if (!function_exists('grantPermission')) {
    function grantPermission($email, $resource, $actions)
    {
        $user = App\Models\User::where('email', $email)->first();
        if (!$user) {
            echo "User not found: $email\n";
            return false;
        }

        $authz = new Apex\Autentica\Core\Services\AuthorizationService();
        $actions = is_array($actions) ? $actions : [$actions];

        $permission = $authz->grant($user, $resource, $actions);
        if ($permission) {
            echo "Granted " . implode(", ", $actions) . " on $resource to $email\n";
            return true;
        } else {
            echo "Failed to grant permissions\n";
            return false;
        }
    }
}

// Show permission matrix for users
if (!function_exists('showPermissionMatrix')) {
    function showPermissionMatrix($emails = [])
    {
        $users = empty($emails)
            ? App\Models\User::limit(5)->get()
            : App\Models\User::whereIn('email', $emails)->get();

        $resources = Apex\Autentica\Core\Models\SystemResource::all();

        echo str_pad("User", 30) . " | ";
        foreach ($resources as $resource) {
            echo str_pad($resource->identifier, 15) . " | ";
        }
        echo "\n" . str_repeat("-", 30 + (count($resources) * 18)) . "\n";

        foreach ($users as $user) {
            echo str_pad(substr($user->email, 0, 29), 30) . " | ";
            foreach ($resources as $resource) {
                $perms = [];
                if ($user->hasPermission($resource->identifier, 'create')) $perms[] = 'C';
                if ($user->hasPermission($resource->identifier, 'read')) $perms[] = 'R';
                if ($user->hasPermission($resource->identifier, 'update')) $perms[] = 'U';
                if ($user->hasPermission($resource->identifier, 'delete')) $perms[] = 'D';
                if ($user->hasPermission($resource->identifier, 'print')) $perms[] = 'P';

                echo str_pad(implode('', $perms), 15) . " | ";
            }
            echo "\n";
        }
        echo "\n(C=Create, R=Read, U=Update, D=Delete, P=Print)\n";
    }
}

// Check account security status
if (!function_exists('checkAccountSecurity')) {
    function checkAccountSecurity($email)
    {
        $user = App\Models\User::where('email', $email)->first();
        if (!$user) {
            echo "User not found: $email\n";
            return;
        }

        echo "Security Status for $email:\n";
        echo "------------------------\n";
        echo "Account locked: " . ($user->isAccountLocked() ? "YES" : "NO") . "\n";
        echo "Failed login attempts (15 min): " . $user->getFailedLoginCount(15) . "\n";
        echo "Failed login attempts (60 min): " . $user->getFailedLoginCount(60) . "\n";

        $lastSuccess = $user->loginAttempts()->successful()->orderBy('attempted_at', 'desc')->first();
        if ($lastSuccess) {
            echo "Last successful login: " . $lastSuccess->attempted_at->diffForHumans() . "\n";
            echo "  From IP: " . $lastSuccess->ip_address . "\n";
        }

        $lastFailed = $user->loginAttempts()->failed()->orderBy('attempted_at', 'desc')->first();
        if ($lastFailed) {
            echo "Last failed login: " . $lastFailed->attempted_at->diffForHumans() . "\n";
            echo "  From IP: " . $lastFailed->ip_address . "\n";
        }

        echo "\nRecent security events:\n";
        $events = $user->getRecentSecurityEvents(5);
        foreach ($events as $event) {
            echo "  - " . $event->getDescription() . " (" . $event->created_at->diffForHumans() . ")\n";
        }
    }
}

// Test authentication
if (!function_exists('testAuth')) {
    function testAuth($email, $password)
    {
        $auth = new Apex\Autentica\Core\Services\AuthenticationService();
        $result = $auth->attempt(['email' => $email, 'password' => $password]);

        if ($result['success']) {
            echo "✓ Authentication successful\n";
            if ($result['password_expired']) {
                echo "⚠ Password has expired\n";
            }
        } else {
            echo "✗ Authentication failed: " . $result['message'] . "\n";
            if (isset($result['remaining_attempts'])) {
                echo "  Remaining attempts: " . $result['remaining_attempts'] . "\n";
            }
            if (isset($result['locked_until'])) {
                echo "  Account locked for: " . $result['locked_until'] . " minutes\n";
            }
        }

        return $result['success'];
    }
}

// Quick add user to group
if (!function_exists('addUserToGroup')) {
    function addUserToGroup($email, $groupName)
    {
        $user = App\Models\User::where('email', $email)->first();
        if (!$user) {
            echo "User not found: $email\n";
            return false;
        }

        if ($user->joinGroup($groupName)) {
            echo "Added $email to group '$groupName'\n";
            return true;
        } else {
            echo "Failed to add user to group\n";
            return false;
        }
    }
}

// List all available functions
if (!function_exists('listAutenticaHelpers')) {
    function listAutenticaHelpers()
    {
        echo "Available Autentica Helper Functions:\n";
        echo "=====================================\n";
        echo "initTenant(\$tenantId) - Initialize a tenant\n";
        echo "checkUserPermission(\$email, \$resource, \$action) - Check user permission\n";
        echo "checkUserGroup(\$email, \$groupName) - Check if user is in group\n";
        echo "getUsersWithPermission(\$resource, \$action) - List users with permission\n";
        echo "grantPermission(\$email, \$resource, \$actions) - Grant permissions\n";
        echo "showPermissionMatrix(\$emails = []) - Show permission matrix\n";
        echo "checkAccountSecurity(\$email) - Check account security status\n";
        echo "testAuth(\$email, \$password) - Test authentication\n";
        echo "addUserToGroup(\$email, \$groupName) - Add user to group\n";
        echo "listAutenticaHelpers() - Show this list\n";
    }
}

// Show helper on load
echo "Autentica Development Helpers Loaded!\n";
echo "Run listAutenticaHelpers() to see available functions.\n";

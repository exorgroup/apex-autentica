# APEX Autentica - Laravel Authentication & Authorization Package

[![Latest Version on Packagist](https://img.shields.io/packagist/v/apex/autentica.svg?style=flat-square)](https://packagist.org/packages/apex/autentica)
[![Total Downloads](https://img.shields.io/packagist/dt/apex/autentica.svg?style=flat-square)](https://packagist.org/packages/apex/autentica)
[![License](https://img.shields.io/packagist/l/apex/autentica.svg?style=flat-square)](https://packagist.org/packages/apex/autentica)

**APEX Autentica** is an enterprise-grade authentication and authorization package for Laravel applications. It provides advanced security features including multi-factor authentication (MFA), comprehensive permission management, OAuth2 social authentication, and security event logging.

## Features

### 🔐 **Core Authentication**
- Multi-factor authentication (TOTP, backup codes)
- OAuth2 social authentication (Google, Facebook, GitHub, etc.)
- Session management with device tracking
- Password history and complexity enforcement
- Security event logging and monitoring

### 🛡️ **Authorization System**
- Granular permission system with CRUD + custom permissions
- Role-based access control (RBAC)
- Resource-based permissions
- Permission caching for optimal performance
- Group-based permission inheritance

### 🔒 **Enterprise Security**
- Failed login attempt tracking and account lockout
- Trusted device management
- Security audit trails
- Comprehensive input validation and sanitization
- SHA512 signatures for data integrity

### ⚡ **Performance**
- Permission caching system
- Optimized database queries
- Lazy loading of related models
- Efficient session management

## Installation

You can install the package via Composer:

```bash
composer require apex/autentica
```

### Laravel Auto-Discovery

The service provider will be automatically registered via Laravel's package auto-discovery feature.

### Publish Configuration

Publish the configuration files:

```bash
php artisan vendor:publish --tag=autentica-config
```

### Publish Migrations

The package automatically detects your application architecture:

```bash
# Auto-detects and publishes to correct location
php artisan vendor:publish --tag=autentica-migrations
php artisan migrate
```

**Multi-tenancy auto-detection:**
- ✅ Detects existing `migrations/tenant/` folder
- ✅ Detects Stancl Tenancy package installation  
- ✅ Can be overridden with `AUTENTICA_TENANCY_ENABLED=true/false`
- ✅ Defaults to single-tenancy if detection is inconclusive

### Publish Language Files

Publish the language files (optional):

```bash
php artisan vendor:publish --tag=autentica-lang
```

For multi-tenant applications:
```bash
php artisan tenants:migrate
```

## Quick Start

### 1. Basic Setup

After installation, configure your authentication settings in `config/autentica/auth.php`:

```php
return [
    'mfa' => [
        'enabled' => true,
        'issuer' => 'Your App Name',
        'algorithm' => 'sha1',
    ],
    'session' => [
        'concurrent_sessions' => 3,
        'track_devices' => true,
    ],
    // ... more configuration options
];
```

### 2. User Model Configuration

Add the Autentica traits to your User model:

```php
use Apex\Autentica\Core\Traits\HasPermissions;
use Apex\Autentica\Core\Traits\HasGroups;

class User extends Authenticatable
{
    use HasPermissions, HasGroups;
    
    // Your existing user model code...
}
```

### 3. Using Permissions

#### Check Permissions
```php
// Check if user has specific permission
if (auth()->user()->hasPermission('users.create')) {
    // User can create users
}

// Check multiple permissions
if (auth()->user()->hasAnyPermission(['users.edit', 'users.delete'])) {
    // User can edit OR delete users
}

// Check all permissions
if (auth()->user()->hasAllPermissions(['users.edit', 'users.view'])) {
    // User can edit AND view users
}
```

#### Assign Permissions
```php
// Assign permission to user
auth()->user()->givePermission('posts.create');

// Assign multiple permissions
auth()->user()->givePermissions(['posts.create', 'posts.edit']);

// Remove permission
auth()->user()->revokePermission('posts.delete');
```

### 4. Using Groups (Roles)

```php
// Assign user to group
auth()->user()->assignToGroup('moderator');

// Check if user belongs to group
if (auth()->user()->belongsToGroup('admin')) {
    // User is an admin
}

// Remove user from group
auth()->user()->removeFromGroup('moderator');
```

### 5. Multi-Factor Authentication

```php
use Apex\Autentica\Core\Services\AuthenticationService;

// Generate MFA setup for user
$auth = app(AuthenticationService::class);
$qrCode = $auth->generateMfaSetup(auth()->user());

// Verify MFA token
$isValid = $auth->verifyMfaToken(auth()->user(), $token);
```

## Configuration

### Architecture Auto-Detection

APEX Autentica automatically detects your application architecture using this priority order:

1. **Explicit Configuration** - If `AUTENTICA_TENANCY_ENABLED` is set to `true` or `false`
2. **Tenant Migrations Folder** - If `database/migrations/tenant/` exists
3. **Stancl Tenancy Package** - If Stancl Tenancy is installed
4. **Default Fallback** - Defaults to single-tenancy mode

**Detection Results:**
- **Multi-tenant detected**: Migrations publish to `database/migrations/tenant/`
- **Single-tenant detected**: Migrations publish to `database/migrations/`

**Override Detection:**
```env
# Force multi-tenancy
AUTENTICA_TENANCY_ENABLED=true

# Force single-tenancy  
AUTENTICA_TENANCY_ENABLED=false

# Use auto-detection (default)
AUTENTICA_TENANCY_ENABLED=auto
```

### Authentication Configuration

The main configuration file is located at `config/autentica/auth.php`:

```php
return [
    'mfa' => [
        'enabled' => true,
        'issuer' => env('MFA_ISSUER', 'APEX App'),
        'algorithm' => 'sha1', // sha1, sha256, sha512
        'period' => 30,
        'window' => 1,
        'backup_codes' => [
            'enabled' => true,
            'count' => 8,
        ],
    ],
    
    'session' => [
        'concurrent_sessions' => 3,
        'track_devices' => true,
        'trusted_devices' => [
            'enabled' => true,
            'duration' => 30, // days
        ],
    ],
    
    'security' => [
        'failed_attempts' => [
            'max_attempts' => 5,
            'lockout_duration' => 15, // minutes
        ],
        'password_history' => [
            'enabled' => true,
            'remember_last' => 12,
        ],
    ],
];
```

### Permission Configuration

Configure permissions in `config/autentica/permissions.php`:

```php
return [
    'cache' => [
        'enabled' => true,
        'ttl' => 3600, // 1 hour
        'key_prefix' => 'autentica_permissions_',
    ],
    
    'default_permissions' => [
        'users' => ['view', 'create', 'edit', 'delete'],
        'posts' => ['view', 'create', 'edit', 'delete', 'publish'],
    ],
];
```

## Advanced Usage

### Custom Permissions

Create custom permissions beyond CRUD operations:

```php
use Apex\Autentica\Core\Models\Permission;
use Apex\Autentica\Core\Models\SystemResource;

// Create a system resource
$resource = SystemResource::create([
    'name' => 'reports',
    'description' => 'Financial Reports',
]);

// Create custom permission
$permission = Permission::create([
    'name' => 'export',
    'system_resource_id' => $resource->id,
]);

// Assign to user
auth()->user()->givePermission('reports.export');
```

### Security Events

Monitor security events in your application:

```php
use Apex\Autentica\Core\Models\SecurityEvent;

// Log custom security event
SecurityEvent::create([
    'user_id' => auth()->id(),
    'event_type' => 'sensitive_data_access',
    'description' => 'User accessed financial reports',
    'ip_address' => request()->ip(),
]);

// Query security events
$recentEvents = SecurityEvent::where('user_id', auth()->id())
    ->where('created_at', '>=', now()->subDays(7))
    ->get();
```

### Permission Caching

The package automatically caches permissions for optimal performance. You can manually clear the cache:

```php
use Apex\Autentica\Core\Services\PermissionCache;

$cache = app(PermissionCache::class);

// Clear cache for specific user
$cache->clearUserPermissions(auth()->id());

// Clear all permission cache
$cache->clearAllPermissions();
```

## Testing

Run the test suite:

```bash
composer test
```

Run tests with coverage:

```bash
composer test-coverage
```

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this package.

## Security

If you discover any security-related issues, please email info@exorgroup.com instead of using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

## Credits

- [EXOR Group](https://github.com/exorgroup)
- [All Contributors](../../contributors)

## Support

For support, please contact support@exorgroup.com or create an issue on GitHub.
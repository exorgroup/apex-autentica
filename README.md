# APEX Autentica

[![License](https://img.shields.io/badge/licence-MIT%20Core%20%2F%20Commercial%20Pro-blue.svg?style=flat-square)](#licence)

Authentication and authorization for Laravel: groups, resource permissions, multi-factor
authentication, session tracking and a security audit trail.

Two halves, split by directory. **Core** (`src/Core/`, MIT) is groups, permissions and the
security log. **Pro** (`src/Pro/`, commercial) adds MFA, session management, trusted devices,
social auth and API tokens. Core never references Pro; an application using Core alone is a
pure MIT deployment.

- [Installation](#installation)
- [Permissions](#permissions) — and see [PERMISSIONS.md](PERMISSIONS.md) for the full model
- [Groups](#groups)
- [Multi-factor authentication](#multi-factor-authentication-pro)
- [Sessions and the security log](#sessions-and-the-security-log-pro)
- [Frontend helpers](#frontend-helpers)
- [Diagnostics](#diagnostics)
- [Upgrading](#upgrading)

## Installation

```bash
composer require exorgroup/apex-autentica
php artisan vendor:publish --tag=autentica-migrations
php artisan vendor:publish --tag=autentica-config
php artisan migrate
```

For Pro, also publish its migrations and config — they are separately tagged so a Core-only
installation never creates Pro tables:

```bash
php artisan vendor:publish --tag=autentica-pro-migrations
php artisan vendor:publish --tag=autentica-pro-config
php artisan migrate
```

Every table is prefixed `au10_`, so nothing collides with your own schema or with Laravel's
`sessions` table.

### User model

```php
use Apex\Autentica\Core\Traits\HasGroups;
use Apex\Autentica\Core\Traits\HasPermissions;
use Apex\Autentica\Core\Traits\HasSecurityEvents;

class User extends Authenticatable
{
    use HasGroups, HasPermissions, HasSecurityEvents;
}
```

The package finds your user model through `config('auth.providers.users.model')` — it never
references `App\Models\User` itself, so a renamed or relocated model works without changes.

### Multi-tenancy

Migrations live under `database/tenant/migrations/` in the package and publish to whichever
path suits the host application. Detection order:

1. `AUTENTICA_TENANCY_ENABLED` set explicitly to `true` or `false`
2. an existing `database/migrations/tenant/` folder
3. `stancl/tenancy` installed
4. otherwise single-tenant

Single-tenant is the default and needs no configuration. The same code serves both.

## Permissions

A permission is a row joining a **holder** (a user or a group) to a **system resource**,
carrying six booleans:

| Column | Letter | Meaning |
|---|---|---|
| `can_create` | `c` | create |
| `can_read` | `r` | read |
| `can_update` | `u` | update |
| `can_delete` | `d` | delete |
| `can_print` | `p` | print / export |
| `can_history` | `h` | view history / audit |

Resources are identified by a string, not a class name, and form a tree:

```php
use Apex\Autentica\Core\Models\SystemResource;

SystemResource::createOrUpdate([
    'identifier' => 'invoices',
    'name' => 'Invoices',
    'type' => 'model',        // model | function | module | page
    'parent_id' => $module->id,
]);
```

### Checking

`hasPermission()` takes the **resource** and the **action** as separate arguments. There is no
dotted `resource.action` string form.

```php
$user->hasPermission('invoices', 'read');                 // one action
$user->hasPermission('invoices', ['update', 'delete']);   // any of these
$user->hasAnyPermission('invoices', ['update', 'delete']);
$user->hasAllPermissions('invoices', ['read', 'print']);
```

Checks read from a per-user cache built on first use. It is invalidated automatically on
grant, revoke and sync; clear it by hand with `$user->clearPermissionCache()`.

### Granting

```php
$user->grantPermission('invoices', ['read', 'print']);
$user->syncPermissions('invoices', ['read']);   // exactly these, nothing else
$user->revokePermission('invoices', ['print']); // named actions
$user->revokePermission('invoices');            // the whole row
```

Groups take the same calls through `Group::grantPermission()` and `Group::revokePermission()`.

### Custom permissions

Anything outside the six booleans goes in `custom_permissions` as a comma-separated list, and
`hasPermission()` matches against it transparently:

```php
$user->grantPermission('invoices', ['read', 'approve']); // approve is stored as custom
$user->hasPermission('invoices', 'approve');             // true
```

See [PERMISSIONS.md](PERMISSIONS.md) for resolution order between user and group grants,
the caching contract, and how to model a permission matrix screen.

## Groups

```php
$user->joinGroup('Administrators');       // by name, id or model
$user->leaveGroup($group);
$user->syncGroups(['Organisers']);        // exactly these
$user->belongsToGroup('Administrators');
$user->belongsToAnyGroup(['Organisers', 'Coordinators']);
$user->getGroupNames();
```

Membership writes are wrapped in a transaction and **throw `AutenticaException` on failure**
rather than returning false. This matters: `syncGroups()` detaches before it attaches, so a
swallowed write error would leave the user in no group at all — silently stripping their
access. Let the exception surface.

## Multi-factor authentication (Pro)

```php
use Apex\Autentica\Pro\Services\TOTPService;
use Apex\Autentica\Pro\Services\MfaBackupService;
use Apex\Autentica\Pro\Services\MfaService;

$totp = app(TOTPService::class);
$secret = $totp->generateSecret($user);
$totp->enableTOTP($user, $secret);            // stored unverified
$totp->verifyCode($user, $code, true);        // true marks it verified
$totp->isEnabled($user);                      // only true once verified

app(MfaBackupService::class)->generateBackupCodes($user);

// Everything at once, across every method, with an audit entry naming who did it.
app(MfaService::class)->disableAllFor($user, $admin);
app(MfaService::class)->enabledAmong($userIds);  // bulk, for list screens
```

Enrolment stores the secret with `verified_at = null`, and `isEnabled()` requires
`verified_at`. Somebody who scans a QR code and then closes the tab is not locked out of their
own account.

Prefer `MfaService::disableAllFor()` over calling `disableTOTP()` and `deleteAllBackupCodes()`
yourself. The two coincide only while TOTP is the single wired method; `au10_mfa_configs.method`
already allows `totp`, `sms` and `email`, and hand-written sequences quietly reset half of it
once a second method appears.

## Sessions and the security log (Pro)

Autentica subscribes to the framework's own `Login`, `Logout`, `Failed`, `Lockout` and
`PasswordReset` events, so the audit trail covers every path that authenticates — form login,
remember cookie, API guard, programmatic `Auth::login()` — without instrumenting controllers.

```php
use Apex\Autentica\Pro\Services\SessionManager;

$sessions = app(SessionManager::class);
$sessions->getActiveSessions($user);
$sessions->endSession($user, $trackedId);              // revoke one device
$sessions->endAllOtherSessions($user, session()->getId());
```

Register the middleware in `bootstrap/app.php`:

```php
$middleware->web(append: [
    \Apex\Autentica\Pro\Middleware\TrackSessionActivity::class,
]);
```

**The middleware is not optional.** It is what creates the tracking row, not the `Login`
event — and for a specific reason. Laravel fires `Login` from `Auth::attempt()`, and the
standard login controller calls `session()->regenerate()` immediately afterwards. A row
recorded during the event carries a session id that is discarded a moment later, which makes
revoke delete a session that does not exist, leaves `is_current` matching nothing, and freezes
`last_activity`. The middleware runs on the way out of the request, once the id is settled.

Revoking terminates the real framework session, not just the tracking row — otherwise the
device stays signed in and only disappears from the list. That works on the `database` and
`file` session drivers; on any other driver Autentica logs a warning rather than pretending,
because there is no store it can reach into.

Retention is handled by a scheduled command:

```php
Schedule::command('autentica:cleanup')->daily();
```

```bash
php artisan autentica:cleanup --dry-run   # report without deleting
```

### Privacy note

`autentica_pro.sessions.location_lookup` is **off by default**. Turning it on adds a blocking
call to a third-party geolocation service on the sign-in path — slow when it answers, slower
when it does not — and sends that service every user's IP address, which is personal data
under the GDPR. Enable it only where the country column is worth both costs.

## Frontend helpers

Permissions are shared to the front end as a compact map and read without a component library,
so an application using its own UI stack still gets the checks:

```php
// HandleInertiaRequests
use Apex\Autentica\Core\Support\PermissionMap;

'auth' => [
    'user' => $request->user(),
    'can' => PermissionMap::for($request->user()),
],
```

```js
import { useCan } from '@apex/autentica';

const { can, canAny, canCustom } = useCan();

can('invoices', 'read');
canAny('invoices', ['update', 'delete']);
```

`can()` and friends are also exported as pure functions taking the map directly, for use
outside a Vue component.

If the package is symlinked from a path repository, Vite needs `preserveSymlinks: true` so
bare imports resolve against the host application's `node_modules`.

## Diagnostics

```bash
php artisan autentica:doctor            # summary
php artisan autentica:doctor --details  # every check
```

Nearly 200 checks covering: every model's table exists; every `$fillable` and cast column
exists; every model using `SoftDeletes` has `deleted_at`; every column named in `withPivot()`
exists on the pivot table; config keys resolve; no orphaned permission or membership rows;
signature verification; and that authentication events are actually being listened to.

It exists because most of these fail silently. A missing pivot column throws inside a `sync()`
that has already detached; logging deliberately swallows its own errors so it cannot break a
sign-in. Run it after publishing migrations and after any upgrade.

## Upgrading

**Re-publish the config, or copy new keys across by hand.** Laravel's `mergeConfigFrom` is
shallow: a published `config/autentica_pro.php` that predates a new nested setting keeps its
own version of the parent array, and the new key never appears. The code falls back to its
default, so nothing breaks visibly — it just silently ignores what you thought you configured.
`autentica:doctor` warns when the published config is missing keys the package expects.

## Testing

```bash
composer test
```

## Licence

Dual-licensed by directory:

| Part | Location | Licence |
|---|---|---|
| **Core** — groups, resource permissions, security events | `src/Core/` | **MIT** — see [LICENSE](LICENSE) |
| **Pro** — MFA, sessions, trusted devices, social auth, API tokens | `src/Pro/` | **Commercial** — see [LICENSE-PRO](LICENSE-PRO) |

Core is free to use, modify and redistribute. Pro requires a commercial licence from EXOR
Group Ltd for production use; evaluation and development use is permitted without one. Every
file under `src/Pro/` carries a licence notice in its header.

## Security

Report security issues to info@exorgroup.com rather than the issue tracker.

## Credits

[EXOR Group](https://github.com/exorgroup)

# apex-autentica — agent reference

Authorization, MFA, sessions and security logging for Laravel. Read this before writing any
code that checks a permission, touches group membership, enrols MFA, or reads a session.

The API here is verified against the source. Several plausible-looking alternatives do **not**
exist — they are listed under [Does not exist](#does-not-exist). Do not invent method names.

## Setup facts

- Tables are prefixed `au10_`. Laravel's own `sessions` table is separate and still owned by
  the framework.
- The user model is resolved from `config('auth.providers.users.model')`. Never hard-code
  `App\Models\User` in package-facing code; type-hint `Illuminate\Foundation\Auth\User` and
  resolve concrete classes through `Apex\Autentica\Core\Support\Autentica::userModel()`.
- Traits on the user model: `HasGroups`, `HasPermissions`, `HasSecurityEvents`.
- Config keys live under `autentica.*` (Core) and `autentica_pro.*` (Pro). There is no
  `config/autentica/auth.php` path-style key.
- Core is `src/Core/` (MIT), Pro is `src/Pro/` (commercial). Core must never reference a Pro
  class by symbol — use a string constant with `class_exists()`.

## Permissions

Resource and action are **separate arguments**. Actions are `create read update delete print
history`, or the letters `c r u d p h`.

```php
$user->hasPermission('invoices', 'read');
$user->hasPermission('invoices', ['update', 'delete']);   // any of
$user->hasAnyPermission('invoices', ['update', 'delete']);
$user->hasAllPermissions('invoices', ['read', 'print']);

$user->grantPermission('invoices', ['read', 'print']);
$user->syncPermissions('invoices', ['read']);
$user->revokePermission('invoices', ['print']);
$user->revokePermission('invoices');            // whole row
$user->clearPermissionCache();
```

Controller guard, the standard form in this codebase:

```php
abort_unless($request->user()->hasPermission('users', 'update'), 403);
```

Effective permissions are the union of the user's own and those of every group they belong to.
Most permissive wins; there are no deny rows.

Anything outside the six actions goes to `custom_permissions` automatically and
`hasPermission()` matches it transparently.

Groups: `Group::grantPermission(SystemResource $resource, array $permissions)` — note this one
takes a **model**, not an identifier string, unlike the user trait.

## Groups

```php
$user->joinGroup('Administrators');   // name, id or model
$user->leaveGroup($group);
$user->joinGroups([...]); $user->leaveGroups([...]);
$user->syncGroups(['Organisers']);    // exactly these
$user->belongsToGroup('Administrators');
$user->belongsToAnyGroup([...]); $user->belongsToAllGroups([...]);
$user->getGroupNames(); $user->getGroupIds(); $user->hasGroups(); $user->getPrimaryGroup();
```

Membership writes throw `AutenticaException` on failure. **Do not wrap these in a try/catch
that swallows.** `syncGroups()` detaches before attaching, so a swallowed failure leaves the
user in no group at all and silently strips their access.

## Resources

```php
SystemResource::createOrUpdate([
    'identifier' => 'invoices',   // unique; what hasPermission() takes
    'name' => 'Invoices',
    'type' => 'model',            // model | function | module | page
    'parent_id' => $module->id,
    'menu_order' => 10,
]);
SystemResource::findByIdentifier('invoices');
```

Module identifiers must differ from their children's. `createOrUpdate()` upserts on
`identifier`, so a shared one collapses both rows into a self-parented survivor and removes the
branch from the tree. Prefix modules (`mod_people`).

## Frontend

```php
'can' => \Apex\Autentica\Core\Support\PermissionMap::for($request->user()),
```

```js
import { useCan } from '@apex/autentica';
const { can, canAny, canCustom } = useCan();
can('invoices', 'read');
```

Also exported as pure functions: `can(map, resource, actions)`, `canAny`, `canCustom`,
`toLetter`, `ACTIONS`.

## MFA (Pro)

```php
$totp = app(TOTPService::class);
$secret = $totp->generateSecret($user);        // takes the user
$totp->enableTOTP($user, $secret);             // takes user AND secret
$totp->verifyCode($user, $code, true);         // third arg marks verified
$totp->isEnabled($user);
$totp->disableTOTP($user);

app(MfaBackupService::class)->generateBackupCodes($user);
app(MfaBackupService::class)->getUnusedCodesCount($user);
app(MfaBackupService::class)->deleteAllBackupCodes($user);

app(MfaService::class)->isEnabledFor($user);
app(MfaService::class)->enabledAmong($userIds);            // bulk — use for list screens
app(MfaService::class)->disableAllFor($user, $actor);      // returns
                                    // ['methods'=>int,'backup_codes'=>int,'was_enabled'=>bool]
```

**Use `MfaService::disableAllFor()` for any "reset this person's MFA" action.** Calling
`disableTOTP()` + `deleteAllBackupCodes()` by hand is correct only while TOTP is the sole wired
method; `au10_mfa_configs.method` already allows `totp`, `sms`, `email`.

Enrolment stores the secret with `verified_at = null` and `isEnabled()` requires
`verified_at` — abandoned setup must not lock anyone out. Preserve that.

## Sessions and logging (Pro)

Logging is automatic: `AuthEventSubscriber` listens to `Login`, `Logout`, `Failed`, `Lockout`,
`PasswordReset`. Do not add manual `logSuccessfulLogin()` calls in login controllers; you will
get duplicates.

```php
$sessions = app(SessionManager::class);
$sessions->getActiveSessions($user);
$sessions->endSession($user, $trackedRowId);               // revoke — terminates for real
$sessions->endAllOtherSessions($user, session()->getId());
$sessions->forgetSession($sessionId);                      // stop tracking, do not terminate
```

`TrackSessionActivity` middleware must be registered in the `web` group. **It creates the
tracking row — the `Login` event deliberately does not.** Laravel fires `Login` from
`Auth::attempt()` and the login controller calls `session()->regenerate()` right after, so a row
written during the event carries an id that is immediately discarded: revoke then deletes
nothing, `is_current` matches nothing, `last_activity` never moves. If you are tempted to
"simplify" by moving row creation back onto the event, do not.

Custom events:

```php
$user->logSecurityEvent('invoice_exported', ['invoice_id' => $id]);
$user->getRecentSecurityEvents(10);
$user->getFailedLoginCount(15);
$user->isAccountLocked();
```

Never send `session_id` from `au10_sessions` to a browser. Build session payloads field by
field.

## Commands

```bash
php artisan autentica:doctor [--details]   # run after migrations, upgrades, or odd behaviour
php artisan autentica:cleanup [--dry-run]  # retention; schedule daily
```

`--details` is the verbose flag, not `-v` (that collides with Artisan's own).

## Traps

1. **Soft deletes vs unique indexes.** `au10_permissions` and `au10_mfa_configs` soft-delete,
   but their unique indexes ignore `deleted_at`. Any code creating these rows must look
   `withTrashed()` and restore, or the second grant/enrolment hits a constraint violation
   forever. `Permission::createFor()` and `TOTPService::enableTOTP()` already do this — match
   the pattern in new code.
2. **Session id regeneration.** See above. The single most expensive bug in this package's
   history.
3. **Revoke must terminate the framework session**, not just the tracking row, or the device
   stays signed in. Only the `database` and `file` session drivers can be reached.
4. **Shallow config merge.** A published `config/autentica_pro.php` predating a new nested key
   hides it — the default silently applies instead. Re-publish after upgrading.
5. **`hasPermission()` fails closed.** It logs and returns false on any exception, so a broken
   cache backend is indistinguishable from "no access". Read the log before touching data.
6. **A wrong resource identifier returns false silently.** There is no error for a resource
   that does not exist.
7. **Flush the permission cache** after bulk changes to resources or group permissions, or the
   database will be right while the application stays wrong until the TTL expires.
8. **Logging swallows its own errors** by design — it must never break a sign-in. That means a
   broken audit trail is invisible. `autentica:doctor` is how you find out.

## Does not exist

Do not write these. They look reasonable and are not in the source:

| Wrong | Right |
|---|---|
| `hasPermission('users.create')` | `hasPermission('users', 'create')` |
| `givePermission()` / `givePermissions()` | `grantPermission($resource, array $actions)` |
| `assignToGroup()` / `removeFromGroup()` | `joinGroup()` / `leaveGroup()` |
| `AuthenticationService::generateMfaSetup()` | `TOTPService::generateSecret()` + `enableTOTP()` |
| `PermissionCache` service class | `$user->clearPermissionCache()` |
| `config('autentica.mfa.*')` | `config('autentica_pro.totp.*')` |
| `SecurityEvent` with a `description` column | `event_data` (array, cast to JSON) |
| `SystemResource` with only `name` + `description` | `identifier`, `name`, `type`, `parent_id` |

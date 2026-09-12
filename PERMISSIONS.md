# The Autentica permission model

Everything an application asks Autentica reduces to one question: *may this holder take this
action on this resource?* This describes how that is stored, how it resolves, and how to build
the screens that manage it.

- [Shape](#shape)
- [Resources](#resources)
- [Actions](#actions)
- [Holders and resolution](#holders-and-resolution)
- [Caching](#caching)
- [Building a permission matrix](#building-a-permission-matrix)
- [Keeping resources in step with the application](#keeping-resources-in-step-with-the-application)
- [Traps](#traps)

## Shape

Two tables carry the whole model.

**`au10_system_resources`** — the things that can be protected. A tree, keyed by a string
identifier rather than a class name, so a resource can stand for a page or an operation and not
only an Eloquent model.

| Column | Notes |
|---|---|
| `identifier` | unique; what application code passes to `hasPermission()` |
| `name` | display label |
| `type` | `model`, `function`, `module` or `page` |
| `parent_id` | self-reference; `module` rows are usually the parents |
| `menu_order` | display ordering |

**`au10_permissions`** — one row per holder per resource.

| Column | Notes |
|---|---|
| `permissionable_type` / `permissionable_id` | polymorphic: a user or a group |
| `system_resource_id` | what it applies to |
| `can_create` … `can_history` | six booleans |
| `custom_permissions` | comma-separated list for anything outside the six |
| `signature` | tamper-evidence, see the signing section of the README |

There is no separate "role" table. A role *is* a group, and a group holds permissions the same
way a user does.

## Resources

Identifiers are yours to choose, but they are the contract between the database and every
`hasPermission()` call in the codebase, so pick them deliberately and do not rename casually.

```php
use Apex\Autentica\Core\Models\SystemResource;

$module = SystemResource::createOrUpdate([
    'identifier' => 'mod_people',
    'name' => 'People',
    'type' => 'module',
    'menu_order' => 60,
]);

SystemResource::createOrUpdate([
    'identifier' => 'users',
    'name' => 'Users',
    'type' => 'model',
    'parent_id' => $module->id,
]);
```

**Give a module a different identifier from its children.** `createOrUpdate()` upserts on
`identifier`, so a module and a child sharing one identifier become a single row that overwrites
itself and ends up its own parent — taking the whole branch out of the tree. Prefixing module
identifiers (`mod_people`) keeps them distinct from the resources beneath them.

## Actions

Six fixed actions, each a boolean column, each with a single-letter form used by the compact
map and the matrix UI:

| Action | Letter | Column |
|---|---|---|
| create | `c` | `can_create` |
| read | `r` | `can_read` |
| update | `u` | `can_update` |
| delete | `d` | `can_delete` |
| print | `p` | `can_print` |
| history | `h` | `can_history` |

`print` covers exports and reports; `history` covers audit views. They exist as first-class
columns because both are commonly granted to people who must not be able to change anything.

Anything else — `approve`, `refund`, `publish` — goes into `custom_permissions`, and
`hasPermission()` checks it without the caller needing to know which kind it is:

```php
$user->grantPermission('invoices', ['read', 'approve']);
$user->hasPermission('invoices', 'approve'); // true
```

## Holders and resolution

A user's effective permissions are the union of:

1. permissions granted to the user directly, and
2. permissions granted to every group the user belongs to.

**Most permissive wins.** If any source allows the action, it is allowed; there is no deny row
and no precedence order to reason about. Removing access means removing the grant, not adding a
denial — so when someone unexpectedly has access, look for the group that carries it rather
than for something overriding something else.

This is deliberate. Deny rules force every check to resolve a conflict, and the resolution is
never obvious to the person reading the screen.

```php
$user->hasPermission('invoices', 'read');
$user->hasAnyPermission('invoices', ['update', 'delete']);
$user->hasAllPermissions('invoices', ['read', 'print']);
```

`hasPermission()` also accepts an array, where it means *any of these*:

```php
$user->hasPermission('invoices', ['update', 'delete']); // same as hasAnyPermission
```

## Caching

`getCachedPermissions()` builds the flattened map once per user and caches it under
`config('autentica.permissions.cache')`. Grant, revoke and sync clear it for that user.

Clear it yourself after changing group membership or after a bulk import:

```php
$user->clearPermissionCache();
```

A command that rewrites resources or group permissions wholesale should flush the cache when it
finishes. Otherwise the database is right and the application is wrong until the TTL expires —
the most confusing failure in this whole subsystem, because everything looks correct.

## Building a permission matrix

`PermissionMap` produces a compact structure — resource identifier to action letters — small
enough to ship on every page and to render a grid from.

```php
use Apex\Autentica\Core\Support\PermissionMap;

PermissionMap::for($user);
// ['invoices' => 'rp', 'users' => 'crud', ...]
```

Share it once from your Inertia middleware and read it in the client:

```js
import { useCan } from '@apex/autentica';

const { can, canAny, canCustom } = useCan();
can('invoices', 'read');
```

For an editing screen, hand the group's letters back the same way they arrived. A letters
string is the whole state of one cell-row, which keeps the payload and the validation trivial:

```php
$request->validate([
    'permissions' => ['array'],
    'permissions.*' => ['string', 'regex:/^[crudph]*$/'],
]);
```

Two rules worth building in:

**An empty string means no permission at all, so delete the row** rather than storing six
falses. A row of nothing but `false` is indistinguishable in effect but shows up in every
diagnostic as a grant.

**Never let the last administrator be edited out.** Lock the administrator group in the UI, and
enforce it server-side too — a permission screen that can remove its own author's access is one
click away from an unrecoverable system.

## Keeping resources in step with the application

Resources describe the application, so they belong in code, not in a one-off seeder that drifts.
Define the tree in a command, run it on deploy, and have it prune what it no longer defines:

```php
php artisan autentica:sync            // apply
php artisan autentica:sync --dry-run  // show what would change
```

A sync command should: upsert every resource; upsert group permissions from a declared matrix;
delete resources it no longer defines (so a removed feature stops appearing on the matrix); and
flush the permission cache at the end.

Prune with care — deleting a resource orphans its permission rows. `autentica:doctor` reports
orphans, and the sync should remove them alongside the resource.

## Traps

**Soft-deleted permissions block re-granting.** `au10_permissions` uses soft deletes, while its
unique index does not know about `deleted_at`. A revoked row therefore still occupies the slot,
and a later grant hits the constraint instead of creating a row. `Permission::createFor()`
handles this by looking `withTrashed()` and restoring — any code writing permission rows
directly must do the same.

**The morph type must match your morph map.** `permissionable_type` stores whatever
`Autentica::morphClass()` resolves to. If the application registers a morph map after rows
already exist, the stored strings no longer match and every permission silently evaluates to
false. Decide on the morph map before going live.

**`hasPermission()` returns false on error.** It logs and fails closed. That is the right
default for an authorization check, but it means a broken cache backend looks exactly like a
user with no access. When permissions vanish for everybody at once, read the log before
touching the data.

**Check the resource identifier before assuming a permission bug.** A typo in the identifier —
`user` for `users` — returns false forever without any error, because a resource that does not
exist simply has no permissions.

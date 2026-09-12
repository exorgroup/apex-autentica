# Changelog

All notable changes to `exorgroup/apex-autentica` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-28

First release used in anger, by APEX TBX. The API is settled enough to build against; the
version stays below 1.0 until a second application has exercised it.

### Added
- Group and resource permission model: `au10_system_resources` (tree, string identifiers)
  × `au10_permissions` (polymorphic holder, six action booleans plus `custom_permissions`)
- `HasPermissions`, `HasGroups` and `HasSecurityEvents` traits, with per-user permission caching
- `PermissionMap` for sharing a compact permission map to a front end, and framework-agnostic
  JS helpers (`can`, `canAny`, `canCustom`) plus a `useCan()` Vue composable
- Core/Pro split by directory with a `class_exists()` seam, so Core never references Pro
- Pro: TOTP multi-factor with backup codes, session tracking, trusted devices, OAuth2, API tokens
- `MfaService` — multi-method operations: `isEnabledFor()`, `enabledAmong()`, `disableAllFor()`
- `AuthEventSubscriber` — automatic logging of login, logout, failed sign-in, lockout and
  password reset by subscribing to the framework's own auth events
- `TrackSessionActivity` middleware — creates the session tracking row and keeps `last_activity`
  current, throttled to one write per minute per session
- `autentica:doctor` — ~197 diagnostic checks over schema, fillables, casts, soft deletes, pivot
  columns, config resolution, orphan rows, signatures and event registration
- `autentica:cleanup` — retention for sessions, devices, used backup codes, tokens and events
- Signing delegated to `exorgroup/apex-signature`: keyed HMAC, self-describing
  `v1:sha512:base64` format, separately rotatable key, off unless `APEX_SIGNATURE_ENABLED`

### Changed
- All tables normalised to a lowercase `au10_` prefix
- The user model is resolved from `config('auth.providers.users.model')` throughout; the package
  no longer references `App\Models\User` anywhere
- Membership writes are wrapped in a transaction and throw `AutenticaException` instead of
  returning false — `syncGroups()` detaches first, so a swallowed failure stripped all access
- `au10_mfa_configs` uniqueness widened from `user_id` to `(user_id, method)`, matching the
  `method` enum that has always allowed `totp`, `sms` and `email`
- IP geolocation on the sign-in path is now opt-in (`AUTENTICA_LOCATION_LOOKUP`, default off)
- Pro token lookup is O(1) via an `{id}|{secret}` token format, rather than scanning every row

### Fixed
- **Session revoke did not revoke.** `endSession()` and `endAllOtherSessions()` deleted only the
  Autentica tracking row, leaving the device signed in and merely absent from the list. They now
  terminate the framework session on the `database` and `file` drivers, and log a warning on
  drivers that cannot be reached rather than reporting success.
- **Session rows recorded a discarded id.** The tracking row was created from the `Login` event,
  which fires before the login controller calls `session()->regenerate()`. Revoke therefore
  targeted a session that never existed, `is_current` matched nothing, and `last_activity` never
  advanced. Row creation moved to `TrackSessionActivity`, which runs once the id is settled.
- **MFA could not be re-enrolled after a reset.** `enableTOTP()` did not consider soft-deleted
  rows while the unique index still counted them, so anyone whose MFA had been disabled hit a
  constraint violation on every subsequent attempt. It now upserts `withTrashed()` and restores.
- **Soft-deleted permissions were permanently un-grantable**, for the same reason.
  `Permission::createFor()` now restores instead of colliding.
- Failed sign-ins against addresses with no account were recorded as login attempts but never as
  security events, hiding exactly the probing worth noticing. They are now logged with a null user.
- `au10_security_events.occurred_at` relied on MySQL's `explicit_defaults_for_timestamp` being
  off to populate itself. It is stamped by the model, so inserts no longer depend on server tuning.
- `HasGroups` wrote a `signature` pivot column that did not exist; the insert threw, the throw was
  swallowed, and `sync()` had already detached — silently emptying group membership. Column added,
  writes now throw, and `doctor` checks every `withPivot()` column against the pivot table.
- Package configuration read namespaces that did not exist, leaving 33 settings inert
- Resource tree corruption when a module and a child shared an identifier

### Security
- Signatures are now a keyed HMAC. The previous implementation hashed without a secret, so anyone
  holding the source could recompute a valid signature for a row they had just altered.
- MFA enrolment stores its secret unverified and `isEnabled()` requires `verified_at`, so an
  abandoned setup cannot lock somebody out of their own account
- Session identifiers are never included in payloads intended for a browser

### Known limitations
- Only TOTP is wired among the methods `au10_mfa_configs` allows
- Revoking a session cannot terminate it on the `cookie`, `array` or custom session drivers
- `mergeConfigFrom` is shallow, so a published config predating a new nested key hides it;
  `autentica:doctor` warns, but re-publishing after an upgrade is still required

<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: HasSecurityEvents trait for logging security-related events. Tracks login attempts,
 *              permission changes, password resets, and other security activities.
 * URL: apex/autentica/src/Core/Traits/HasSecurityEvents.php
 */

namespace Apex\Autentica\Core\Traits;

use Apex\Autentica\Core\Models\SecurityEvent;
use Apex\Autentica\Core\Models\LoginAttempt;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Request;

trait HasSecurityEvents
{
    /**
     * Get all security events for this model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function securityEvents()
    {
        try {
            return $this->hasMany(SecurityEvent::class, 'user_id');
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - securityEvents() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Get all login attempts for this model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function loginAttempts()
    {
        try {
            return $this->hasMany(LoginAttempt::class, 'email', 'email');
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - loginAttempts() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Log a security event.
     *
     * @param string $eventType
     * @param array $eventData
     * @param string|null $ipAddress
     * @param string|null $userAgent
     * @return SecurityEvent
     */
    public function logSecurityEvent(
        string $eventType,
        array $eventData = [],
        ?string $ipAddress = null,
        ?string $userAgent = null
    ): SecurityEvent {
        try {
            return SecurityEvent::create([
                'user_id' => $this->id,
                'event_type' => $eventType,
                'event_data' => $eventData,
                'ip_address' => $ipAddress ?? Request::ip(),
                'user_agent' => $userAgent ?? Request::userAgent(),
            ]);
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - logSecurityEvent() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Log a successful login attempt.
     *
     * @param array $additionalData
     * @return LoginAttempt
     */
    public function logSuccessfulLogin(array $additionalData = []): LoginAttempt
    {
        try {
            $attempt = LoginAttempt::create([
                'email' => $this->email,
                'ip_address' => Request::ip(),
                'user_agent' => Request::userAgent(),
                'successful' => true,
                'attempted_at' => now(),
            ]);

            $this->logSecurityEvent('login_success', array_merge([
                'method' => 'standard',
                'login_attempt_id' => $attempt->id,
            ], $additionalData));

            return $attempt;
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - logSuccessfulLogin() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Log a failed login attempt.
     *
     * @param string $email
     * @param array $additionalData
     * @return LoginAttempt
     */
    public static function logFailedLogin(string $email, array $additionalData = []): LoginAttempt
    {
        try {
            $attempt = LoginAttempt::create([
                'email' => $email,
                'ip_address' => Request::ip(),
                'user_agent' => Request::userAgent(),
                'successful' => false,
                'attempted_at' => now(),
            ]);

            // If user exists, log security event
            $user = static::where('email', $email)->first();
            if ($user) {
                $user->logSecurityEvent('login_failed', array_merge([
                    'login_attempt_id' => $attempt->id,
                ], $additionalData));
            }

            return $attempt;
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - logFailedLogin() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Log a logout event.
     *
     * @param array $additionalData
     * @return SecurityEvent
     */
    public function logLogout(array $additionalData = []): SecurityEvent
    {
        try {
            return $this->logSecurityEvent('logout', array_merge([
                'method' => 'user_initiated',
            ], $additionalData));
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - logLogout() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Log a password change event.
     *
     * @param array $additionalData
     * @return SecurityEvent
     */
    public function logPasswordChange(array $additionalData = []): SecurityEvent
    {
        try {
            return $this->logSecurityEvent('password_changed', array_merge([
                'changed_at' => now()->toDateTimeString(),
            ], $additionalData));
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - logPasswordChange() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Log a password reset request.
     *
     * @param array $additionalData
     * @return SecurityEvent
     */
    public function logPasswordResetRequest(array $additionalData = []): SecurityEvent
    {
        try {
            return $this->logSecurityEvent('password_reset_requested', array_merge([
                'requested_at' => now()->toDateTimeString(),
            ], $additionalData));
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - logPasswordResetRequest() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Log a permission change event.
     *
     * @param string $action
     * @param string $resource
     * @param array $permissions
     * @return SecurityEvent
     */
    public function logPermissionChange(string $action, string $resource, array $permissions): SecurityEvent
    {
        try {
            return $this->logSecurityEvent('permission_changed', [
                'action' => $action, // granted, revoked, modified
                'resource' => $resource,
                'permissions' => $permissions,
                'changed_at' => now()->toDateTimeString(),
            ]);
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - logPermissionChange() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Log a group membership change.
     *
     * @param string $action
     * @param string $groupName
     * @return SecurityEvent
     */
    public function logGroupChange(string $action, string $groupName): SecurityEvent
    {
        try {
            return $this->logSecurityEvent('group_membership_changed', [
                'action' => $action, // joined, left
                'group' => $groupName,
                'changed_at' => now()->toDateTimeString(),
            ]);
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - logGroupChange() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Get recent security events.
     *
     * @param int $limit
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function getRecentSecurityEvents(int $limit = 10)
    {
        try {
            return $this->securityEvents()
                ->orderBy('created_at', 'desc')
                ->limit($limit)
                ->get();
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - getRecentSecurityEvents() method error: ' . $e->getMessage());
            return collect();
        }
    }

    /**
     * Get recent login attempts.
     *
     * @param int $limit
     * @param bool|null $successful
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function getRecentLoginAttempts(int $limit = 10, ?bool $successful = null)
    {
        try {
            $query = $this->loginAttempts()
                ->orderBy('attempted_at', 'desc')
                ->limit($limit);

            if ($successful !== null) {
                $query->where('successful', $successful);
            }

            return $query->get();
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - getRecentLoginAttempts() method error: ' . $e->getMessage());
            return collect();
        }
    }

    /**
     * Get failed login attempts count within a time period.
     *
     * @param int $minutes
     * @return int
     */
    public function getFailedLoginCount(int $minutes = 15): int
    {
        try {
            return $this->loginAttempts()
                ->where('successful', false)
                ->where('attempted_at', '>=', now()->subMinutes($minutes))
                ->count();
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - getFailedLoginCount() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Check if the account is locked due to failed login attempts.
     *
     * @return bool
     */
    public function isAccountLocked(): bool
    {
        try {
            $maxAttempts = config('auth.security.max_login_attempts', 5);
            $lockoutDuration = config('auth.security.lockout_duration', 15);

            $failedAttempts = $this->getFailedLoginCount($lockoutDuration);

            if ($failedAttempts >= $maxAttempts) {
                // Check if there's a successful login after the failed attempts
                $lastSuccess = $this->loginAttempts()
                    ->where('successful', true)
                    ->orderBy('attempted_at', 'desc')
                    ->first();

                $lastFailed = $this->loginAttempts()
                    ->where('successful', false)
                    ->orderBy('attempted_at', 'desc')
                    ->first();

                if (!$lastSuccess || ($lastFailed && $lastFailed->attempted_at->gt($lastSuccess->attempted_at))) {
                    return true;
                }
            }

            return false;
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - isAccountLocked() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get the time until account unlock.
     *
     * @return int Minutes until unlock, 0 if not locked
     */
    public function getUnlockTime(): int
    {
        try {
            if (!$this->isAccountLocked()) {
                return 0;
            }

            $lockoutDuration = config('auth.security.lockout_duration', 15);

            $lastFailedAttempt = $this->loginAttempts()
                ->where('successful', false)
                ->orderBy('attempted_at', 'desc')
                ->first();

            if ($lastFailedAttempt) {
                $unlockTime = $lastFailedAttempt->attempted_at->addMinutes($lockoutDuration);
                return max(0, now()->diffInMinutes($unlockTime, false));
            }

            return 0;
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - getUnlockTime() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get security events by type.
     *
     * @param string $eventType
     * @param int $limit
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function getSecurityEventsByType(string $eventType, int $limit = 10)
    {
        try {
            return $this->securityEvents()
                ->where('event_type', $eventType)
                ->orderBy('created_at', 'desc')
                ->limit($limit)
                ->get();
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - getSecurityEventsByType() method error: ' . $e->getMessage());
            return collect();
        }
    }

    /**
     * Clear old security events.
     *
     * @param int $daysToKeep
     * @return int Number of deleted records
     */
    public function clearOldSecurityEvents(int $daysToKeep = 90): int
    {
        try {
            return $this->securityEvents()
                ->where('created_at', '<', now()->subDays($daysToKeep))
                ->delete();
        } catch (\Exception $e) {
            Log::error('HasSecurityEvents.php - clearOldSecurityEvents() method error: ' . $e->getMessage());
            return 0;
        }
    }
}

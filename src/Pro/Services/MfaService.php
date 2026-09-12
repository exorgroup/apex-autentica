<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Operations that span every multi-factor method, rather than one at a time.
 * File Location: exorgroup/apex-autentica/src/Pro/Services/MfaService.php
 */

namespace Apex\Autentica\Pro\Services;

use Apex\Autentica\Core\Models\SecurityEvent;
use Apex\Autentica\Pro\Models\MfaConfig;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Log;

/**
 * Multi-factor authentication as a whole, across methods.
 *
 * "Reset this person's MFA" and "disable their TOTP" are not the same statement, even though
 * they happen to coincide while TOTP is the only method wired up: au10_mfa_configs.method
 * already allows totp, sms and email. A caller that writes out the individual steps is
 * correct only until the next method is added, and then quietly resets half of it.
 *
 * So the intent lives here, once, and stays right as methods are added.
 */
class MfaService
{
    public function __construct(
        private readonly TOTPService $totp,
        private readonly MfaBackupService $backup,
    ) {
    }

    /**
     * Event type recorded when someone's MFA is reset.
     */
    public const EVENT_RESET = 'mfa_reset';

    /**
     * Is any multi-factor method active for this user?
     *
     * @param User $user
     * @return bool
     */
    public function isEnabledFor(User $user): bool
    {
        try {
            return MfaConfig::where('user_id', $user->getKey())
                ->whereNotNull('verified_at')
                ->exists();
        } catch (\Exception $e) {
            Log::error('MfaService.php - isEnabledFor() method error: ' . $e->getMessage());

            // Fail closed for a read: better to claim MFA is off and let the challenge
            // middleware decide than to lock someone out on a database blip.
            return false;
        }
    }

    /**
     * Which of these users have multi-factor active?
     *
     * The list form exists so a screen showing many accounts asks once instead of once per
     * row. Calling isEnabledFor() in a loop is the same question asked badly.
     *
     * @param array<int|string> $userIds
     * @return array<int|string> The subset that has MFA on, as a plain list
     */
    public function enabledAmong(array $userIds): array
    {
        if (empty($userIds)) {
            return [];
        }

        try {
            return MfaConfig::whereIn('user_id', $userIds)
                ->whereNotNull('verified_at')
                ->distinct()
                ->pluck('user_id')
                ->all();
        } catch (\Exception $e) {
            Log::error('MfaService.php - enabledAmong() method error: ' . $e->getMessage());

            return [];
        }
    }

    /**
     * Remove every multi-factor method from an account, and its backup codes.
     *
     * The recovery path for someone who has lost their authenticator and used up their backup
     * codes. They sign in with their password alone afterwards and can enrol again.
     *
     * @param User $user The account being reset
     * @param User|null $actor Who performed it, for the audit trail
     * @return array{methods: int, backup_codes: int, was_enabled: bool} What was actually cleared
     */
    public function disableAllFor(User $user, ?User $actor = null): array
    {
        $wasEnabled = $this->isEnabledFor($user);

        // Reported so a caller can say "there was nothing to reset" honestly, rather than
        // claiming success for an account that never had MFA.
        $methods = MfaConfig::where('user_id', $user->getKey())->count();

        $this->totp->disableTOTP($user);

        // Anything the specific services do not cover yet — an sms or email row, say.
        MfaConfig::where('user_id', $user->getKey())->delete();

        $codes = $this->backup->deleteAllBackupCodes($user);

        $this->recordReset($user, $actor, $methods, $codes, $wasEnabled);

        return [
            'methods' => $methods,
            'backup_codes' => $codes,
            'was_enabled' => $wasEnabled,
        ];
    }

    /**
     * Note the reset on the account's security log.
     *
     * Removing someone's second factor is exactly the kind of act an audit needs to show,
     * including who did it.
     *
     * @param User $user
     * @param User|null $actor
     * @param int $methods
     * @param int $codes
     * @param bool $wasEnabled
     * @return void
     */
    private function recordReset(User $user, ?User $actor, int $methods, int $codes, bool $wasEnabled): void
    {
        try {
            if (! method_exists($user, 'logSecurityEvent')) {
                return;
            }

            $user->logSecurityEvent(self::EVENT_RESET, [
                'reset_by_user_id' => $actor?->getKey(),
                'reset_by_email' => $actor?->email,
                'methods_removed' => $methods,
                'backup_codes_removed' => $codes,
                'was_enabled' => $wasEnabled,
            ]);
        } catch (\Exception $e) {
            // The reset itself has already happened and matters more than the log line.
            Log::error('MfaService.php - recordReset() method error: ' . $e->getMessage());
        }
    }
}

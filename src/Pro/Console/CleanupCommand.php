<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Prunes stale sessions, devices, tokens, used backup codes and expired security
 *              events according to the retention settings.
 * File Location: exorgroup/apex-autentica/src/Pro/Console/CleanupCommand.php
 */

namespace Apex\Autentica\Pro\Console;

use Apex\Autentica\Core\Models\LoginAttempt;
use Apex\Autentica\Core\Models\SecurityEvent;
use Apex\Autentica\Pro\Services\AuthTokenService;
use Apex\Autentica\Pro\Services\DeviceManagementService;
use Apex\Autentica\Pro\Services\MfaBackupService;
use Apex\Autentica\Pro\Services\SessionManager;
use Illuminate\Console\Command;

/**
 * Housekeeping for the tables that only ever grow.
 *
 * Sessions, login attempts and security events accumulate for as long as an installation
 * runs. Left alone, the sessions list fills with devices that stopped existing months ago and
 * the audit tables grow without bound. The retention numbers already live in config; this is
 * what acts on them.
 */
class CleanupCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'autentica:cleanup
                            {--dry-run : Report what would be removed without removing it}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune expired sessions, inactive devices, used backup codes and old security events';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $retentionDays = (int) config('autentica_pro.maintenance.keep_security_logs_days', 365);

        $this->newLine();
        $this->line('  <options=bold>Autentica Cleanup</>' . ($dryRun ? ' <fg=yellow>(dry run)</>' : ''));
        $this->newLine();

        $cutoff = now()->subDays($retentionDays);

        if ($dryRun) {
            $this->report('expired sessions', $this->countStaleSessions());
            $this->report('inactive trusted devices', $this->countStaleDevices());
            $this->report('security events older than ' . $retentionDays . ' days', SecurityEvent::where('occurred_at', '<', $cutoff)->count());
            $this->report('login attempts older than ' . $retentionDays . ' days', LoginAttempt::where('attempted_at', '<', $cutoff)->count());
            $this->newLine();
            $this->line('  Nothing was removed.');
            $this->newLine();

            return self::SUCCESS;
        }

        $this->report('expired sessions', app(SessionManager::class)->cleanupExpiredSessions());
        $this->report('inactive trusted devices', app(DeviceManagementService::class)->cleanupInactiveDevices());
        $this->report('used backup codes', app(MfaBackupService::class)->cleanupOldUsedCodes());
        $this->report('expired auth tokens', app(AuthTokenService::class)->cleanupExpiredTokens());
        $this->report('security events', SecurityEvent::where('occurred_at', '<', $cutoff)->delete());
        $this->report('login attempts', LoginAttempt::where('attempted_at', '<', $cutoff)->delete());

        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Print one line of the tally.
     *
     * @param string $label
     * @param int $count
     * @return void
     */
    private function report(string $label, int $count): void
    {
        $colour = $count > 0 ? 'green' : 'gray';
        $this->line(sprintf('  <fg=%s>%6d</> %s', $colour, $count, $label));
    }

    /**
     * How many sessions are past the inactivity window.
     *
     * @return int
     */
    private function countStaleSessions(): int
    {
        $hours = (int) config('autentica_pro.sessions.cleanup_hours', 24);

        return \Apex\Autentica\Pro\Models\Session::where('last_activity', '<', now()->subHours($hours))->count();
    }

    /**
     * How many trusted devices are past the inactivity window.
     *
     * @return int
     */
    private function countStaleDevices(): int
    {
        $days = (int) config('autentica_pro.devices.cleanup_days', 90);

        return \Apex\Autentica\Pro\Models\TrustedDevice::where('last_used_at', '<', now()->subDays($days))->count();
    }
}

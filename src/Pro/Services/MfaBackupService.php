<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Service class for managing MFA backup recovery codes including generation, verification, and usage tracking
 * File Location: apex/autentica/src/Pro/Services/MfaBackupService.php
 */

namespace Apex\Autentica\Pro\Services;

use App\Models\User;
use Apex\Autentica\Pro\Models\MfaBackupCode;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class MfaBackupService
{
    /**
     * Get backup codes configuration values
     *
     * @return array
     */
    private function getBackupConfig(): array
    {
        return [
            'default_count' => config('autentica_pro.backup_codes.default_count', 10),
            'code_length' => config('autentica_pro.backup_codes.code_length', 8),
            'format_with_dash' => config('autentica_pro.backup_codes.format_with_dash', true),
            'low_count_warning' => config('autentica_pro.backup_codes.low_count_warning', 2),
            'cleanup_days' => config('autentica_pro.backup_codes.cleanup_days', 90),
        ];
    }

    /**
     * Generate new backup codes for a user.
     *
     * @param User $user
     * @param int $count Number of backup codes to generate
     * @param bool $replaceExisting Whether to replace existing codes
     * @return array Array of plain text backup codes
     * @throws \Exception
     */
    public function generateBackupCodes(User $user, ?int $count = null, bool $replaceExisting = true): array
    {
        try {
            $config = $this->getBackupConfig();
            $count = $count ?? $config['default_count'];
            // Remove existing backup codes if replacing
            if ($replaceExisting) {
                MfaBackupCode::where('user_id', $user->id)->delete();

                Log::info('Existing backup codes removed', [
                    'file' => 'MfaBackupService.php',
                    'method' => 'generateBackupCodes',
                    'user_id' => $user->id
                ]);
            }

            $backupCodes = [];
            $hashedCodes = [];

            // Generate the specified number of backup codes
            for ($i = 0; $i < $count; $i++) {
                $plainCode = $this->generateSingleBackupCode();
                $backupCodes[] = $plainCode;

                $hashedCodes[] = [
                    'user_id' => $user->id,
                    'code' => Hash::make($plainCode),
                    'used_at' => null,
                    'created_at' => now(),
                    'updated_at' => now(),
                ];
            }

            // Bulk insert hashed codes with signatures
            foreach ($hashedCodes as &$codeData) {
                $codeData['signature'] = hash('sha512', implode('|', $codeData));
            }

            MfaBackupCode::insert($hashedCodes);

            Log::info('MFA backup codes generated', [
                'file' => 'MfaBackupService.php',
                'method' => 'generateBackupCodes',
                'user_id' => $user->id,
                'code_count' => $count,
                'replaced_existing' => $replaceExisting
            ]);

            return $backupCodes;
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - generateBackupCodes() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'generateBackupCodes',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Verify a backup code for a user.
     *
     * @param User $user
     * @param string $code
     * @param bool $markAsUsed Whether to mark the code as used after verification
     * @return bool
     * @throws \Exception
     */
    public function verifyBackupCode(User $user, string $code, bool $markAsUsed = true): bool
    {
        try {
            // Get all unused backup codes for the user
            $backupCodes = MfaBackupCode::where('user_id', $user->id)
                ->whereNull('used_at')
                ->get();

            foreach ($backupCodes as $backupCode) {
                if (Hash::check($code, $backupCode->code)) {
                    if ($markAsUsed) {
                        $backupCode->update(['used_at' => now()]);
                    }

                    Log::info('MFA backup code verified successfully', [
                        'file' => 'MfaBackupService.php',
                        'method' => 'verifyBackupCode',
                        'user_id' => $user->id,
                        'backup_code_id' => $backupCode->id,
                        'marked_as_used' => $markAsUsed
                    ]);

                    return true;
                }
            }

            Log::warning('MFA backup code verification failed', [
                'file' => 'MfaBackupService.php',
                'method' => 'verifyBackupCode',
                'user_id' => $user->id
            ]);

            return false;
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - verifyBackupCode() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'verifyBackupCode',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get backup code statistics for a user.
     *
     * @param User $user
     * @return array
     * @throws \Exception
     */
    public function getBackupCodeStats(User $user): array
    {
        try {
            $config = $this->getBackupConfig();

            $totalCodes = MfaBackupCode::where('user_id', $user->id)->count();
            $usedCodes = MfaBackupCode::where('user_id', $user->id)
                ->whereNotNull('used_at')
                ->count();
            $unusedCodes = $totalCodes - $usedCodes;

            $lastGenerated = MfaBackupCode::where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->value('created_at');

            $stats = [
                'total_codes' => $totalCodes,
                'used_codes' => $usedCodes,
                'unused_codes' => $unusedCodes,
                'last_generated' => $lastGenerated,
                'has_codes' => $totalCodes > 0,
                'needs_regeneration' => $unusedCodes <= $config['low_count_warning'],
            ];

            Log::info('Backup code statistics retrieved', [
                'file' => 'MfaBackupService.php',
                'method' => 'getBackupCodeStats',
                'user_id' => $user->id,
                'stats' => $stats
            ]);

            return $stats;
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - getBackupCodeStats() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'getBackupCodeStats',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get unused backup codes count for a user.
     *
     * @param User $user
     * @return int
     * @throws \Exception
     */
    public function getUnusedCodesCount(User $user): int
    {
        try {
            $count = MfaBackupCode::where('user_id', $user->id)
                ->whereNull('used_at')
                ->count();

            Log::info('Unused backup codes count retrieved', [
                'file' => 'MfaBackupService.php',
                'method' => 'getUnusedCodesCount',
                'user_id' => $user->id,
                'unused_count' => $count
            ]);

            return $count;
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - getUnusedCodesCount() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'getUnusedCodesCount',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Delete all backup codes for a user.
     *
     * @param User $user
     * @return int Number of codes deleted
     * @throws \Exception
     */
    public function deleteAllBackupCodes(User $user): int
    {
        try {
            $deleted = MfaBackupCode::where('user_id', $user->id)->delete();

            Log::info('All backup codes deleted', [
                'file' => 'MfaBackupService.php',
                'method' => 'deleteAllBackupCodes',
                'user_id' => $user->id,
                'codes_deleted' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - deleteAllBackupCodes() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'deleteAllBackupCodes',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if user has any backup codes.
     *
     * @param User $user
     * @return bool
     * @throws \Exception
     */
    public function hasBackupCodes(User $user): bool
    {
        try {
            return MfaBackupCode::where('user_id', $user->id)->exists();
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - hasBackupCodes() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'hasBackupCodes',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if user has any unused backup codes.
     *
     * @param User $user
     * @return bool
     * @throws \Exception
     */
    public function hasUnusedBackupCodes(User $user): bool
    {
        try {
            return MfaBackupCode::where('user_id', $user->id)
                ->whereNull('used_at')
                ->exists();
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - hasUnusedBackupCodes() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'hasUnusedBackupCodes',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Clean up used backup codes older than specified days.
     *
     * @param int $daysOld Number of days old
     * @return int Number of codes cleaned up
     * @throws \Exception
     */
    public function cleanupOldUsedCodes(?int $daysOld = null): int
    {
        try {
            $config = $this->getBackupConfig();
            $daysOld = $daysOld ?? $config['cleanup_days'];
            $cutoffDate = now()->subDays($daysOld);

            $deleted = MfaBackupCode::whereNotNull('used_at')
                ->where('used_at', '<', $cutoffDate)
                ->delete();

            Log::info('Old used backup codes cleaned up', [
                'file' => 'MfaBackupService.php',
                'method' => 'cleanupOldUsedCodes',
                'days_old' => $daysOld,
                'codes_deleted' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - cleanupOldUsedCodes() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'cleanupOldUsedCodes',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get backup code usage history for a user.
     *
     * @param User $user
     * @param int $limit
     * @return \Illuminate\Database\Eloquent\Collection
     * @throws \Exception
     */
    public function getUsageHistory(User $user, int $limit = 10): \Illuminate\Database\Eloquent\Collection
    {
        try {
            $history = MfaBackupCode::where('user_id', $user->id)
                ->whereNotNull('used_at')
                ->orderBy('used_at', 'desc')
                ->limit($limit)
                ->get(['id', 'used_at', 'created_at']);

            Log::info('Backup code usage history retrieved', [
                'file' => 'MfaBackupService.php',
                'method' => 'getUsageHistory',
                'user_id' => $user->id,
                'records_count' => $history->count()
            ]);

            return $history;
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - getUsageHistory() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'getUsageHistory',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Generate a single backup code.
     *
     * @return string
     * @throws \Exception
     */
    private function generateSingleBackupCode(): string
    {
        try {
            $config = $this->getBackupConfig();
            $codeLength = $config['code_length'];

            // Use RFC 4648 Base32 alphabet (more secure and standard)
            $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            $code = '';

            for ($i = 0; $i < $codeLength; $i++) {
                $code .= $characters[random_int(0, strlen($characters) - 1)];
            }

            // Format code with dashes for better readability if configured
            if ($config['format_with_dash'] && $codeLength >= 4) {
                $midPoint = intval($codeLength / 2);
                return substr($code, 0, $midPoint) . '-' . substr($code, $midPoint);
            }

            return $code;
        } catch (\Exception $e) {
            Log::error('MfaBackupService.php - generateSingleBackupCode() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupService.php',
                'method' => 'generateSingleBackupCode',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}

<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Service class for trusted device management including device registration, verification, and security monitoring
 * File Location: apex/autentica/src/Pro/Services/DeviceManagementService.php
 */

namespace Apex\Autentica\Pro\Services;

use App\Models\User;
use Apex\Autentica\Pro\Models\TrustedDevice;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class DeviceManagementService
{
    /**
     * Get device management configuration values
     *
     * @return array
     */
    private function getDeviceConfig(): array
    {
        return [
            'max_trusted_devices' => config('autentica_pro.devices.max_trusted_devices', 10),
            'cleanup_days' => config('autentica_pro.devices.cleanup_days', 90),
        ];
    }

    /**
     * Register a new trusted device for a user.
     *
     * @param User $user
     * @param Request $request
     * @param string|null $deviceName Custom device name
     * @return TrustedDevice
     * @throws \Exception
     */
    public function registerTrustedDevice(User $user, Request $request, ?string $deviceName = null): TrustedDevice
    {
        try {
            $deviceId = $this->generateDeviceId($request);
            $deviceInfo = $this->parseDeviceInfo($request);

            // Enforce device limits
            $this->enforceDeviceLimits($user);

            $trustedDevice = TrustedDevice::updateOrCreate(
                [
                    'user_id' => $user->id,
                    'device_id' => $deviceId,
                ],
                [
                    'device_name' => $deviceName ?: $this->generateDeviceName($deviceInfo),
                    'browser' => $deviceInfo['browser'],
                    'platform' => $deviceInfo['platform'],
                    'ip_address' => $request->ip(),
                    'last_used_at' => now(),
                ]
            );

            Log::info('Trusted device registered', [
                'file' => 'DeviceManagementService.php',
                'method' => 'registerTrustedDevice',
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'trusted_device_id' => $trustedDevice->id
            ]);

            return $trustedDevice;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - registerTrustedDevice() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'registerTrustedDevice',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if a device is trusted for a user.
     *
     * @param User $user
     * @param Request $request
     * @return bool
     * @throws \Exception
     */
    public function isDeviceTrusted(User $user, Request $request): bool
    {
        try {
            $deviceId = $this->generateDeviceId($request);

            $exists = TrustedDevice::where('user_id', $user->id)
                ->where('device_id', $deviceId)
                ->exists();

            Log::info('Device trust check performed', [
                'file' => 'DeviceManagementService.php',
                'method' => 'isDeviceTrusted',
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'is_trusted' => $exists
            ]);

            return $exists;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - isDeviceTrusted() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'isDeviceTrusted',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Update device last used timestamp.
     *
     * @param User $user
     * @param Request $request
     * @return bool
     * @throws \Exception
     */
    public function updateDeviceActivity(User $user, Request $request): bool
    {
        try {
            $deviceId = $this->generateDeviceId($request);

            $updated = TrustedDevice::where('user_id', $user->id)
                ->where('device_id', $deviceId)
                ->update([
                    'last_used_at' => now(),
                    'ip_address' => $request->ip(),
                ]);

            if ($updated) {
                Log::info('Device activity updated', [
                    'file' => 'DeviceManagementService.php',
                    'method' => 'updateDeviceActivity',
                    'user_id' => $user->id,
                    'device_id' => $deviceId
                ]);
            }

            return $updated > 0;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - updateDeviceActivity() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'updateDeviceActivity',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get all trusted devices for a user.
     *
     * @param User $user
     * @return \Illuminate\Database\Eloquent\Collection
     * @throws \Exception
     */
    public function getTrustedDevices(User $user): \Illuminate\Database\Eloquent\Collection
    {
        try {
            $devices = TrustedDevice::where('user_id', $user->id)
                ->orderBy('last_used_at', 'desc')
                ->get();

            Log::info('Trusted devices retrieved', [
                'file' => 'DeviceManagementService.php',
                'method' => 'getTrustedDevices',
                'user_id' => $user->id,
                'device_count' => $devices->count()
            ]);

            return $devices;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - getTrustedDevices() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'getTrustedDevices',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Remove a trusted device.
     *
     * @param User $user
     * @param int $deviceId
     * @return bool
     * @throws \Exception
     */
    public function removeTrustedDevice(User $user, int $deviceId): bool
    {
        try {
            $deleted = TrustedDevice::where('id', $deviceId)
                ->where('user_id', $user->id)
                ->delete();

            Log::info('Trusted device removed', [
                'file' => 'DeviceManagementService.php',
                'method' => 'removeTrustedDevice',
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'deleted' => $deleted > 0
            ]);

            return $deleted > 0;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - removeTrustedDevice() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'removeTrustedDevice',
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Remove all trusted devices for a user.
     *
     * @param User $user
     * @return int Number of devices removed
     * @throws \Exception
     */
    public function removeAllTrustedDevices(User $user): int
    {
        try {
            $deleted = TrustedDevice::where('user_id', $user->id)->delete();

            Log::info('All trusted devices removed', [
                'file' => 'DeviceManagementService.php',
                'method' => 'removeAllTrustedDevices',
                'user_id' => $user->id,
                'devices_removed' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - removeAllTrustedDevices() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'removeAllTrustedDevices',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Update device name.
     *
     * @param User $user
     * @param int $deviceId
     * @param string $newName
     * @return bool
     * @throws \Exception
     */
    public function updateDeviceName(User $user, int $deviceId, string $newName): bool
    {
        try {
            $updated = TrustedDevice::where('id', $deviceId)
                ->where('user_id', $user->id)
                ->update(['device_name' => $newName]);

            Log::info('Device name updated', [
                'file' => 'DeviceManagementService.php',
                'method' => 'updateDeviceName',
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'new_name' => $newName,
                'updated' => $updated > 0
            ]);

            return $updated > 0;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - updateDeviceName() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'updateDeviceName',
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get device statistics for a user.
     *
     * @param User $user
     * @return array
     * @throws \Exception
     */
    public function getDeviceStats(User $user): array
    {
        try {
            $config = $this->getDeviceConfig();

            $totalDevices = TrustedDevice::where('user_id', $user->id)->count();
            $activeDevices = TrustedDevice::where('user_id', $user->id)
                ->where('last_used_at', '>', now()->subDays(30))
                ->count();
            $oldestDevice = TrustedDevice::where('user_id', $user->id)
                ->orderBy('created_at', 'asc')
                ->value('created_at');
            $newestDevice = TrustedDevice::where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->value('created_at');

            $stats = [
                'total_devices' => $totalDevices,
                'active_devices' => $activeDevices,
                'inactive_devices' => $totalDevices - $activeDevices,
                'oldest_device' => $oldestDevice,
                'newest_device' => $newestDevice,
                'at_limit' => $totalDevices >= $config['max_trusted_devices'],
            ];

            Log::info('Device statistics retrieved', [
                'file' => 'DeviceManagementService.php',
                'method' => 'getDeviceStats',
                'user_id' => $user->id,
                'stats' => $stats
            ]);

            return $stats;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - getDeviceStats() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'getDeviceStats',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Clean up old inactive devices.
     *
     * @param int $daysInactive Days of inactivity before device is removed
     * @return int Number of devices cleaned up
     * @throws \Exception
     */
    public function cleanupInactiveDevices(?int $daysInactive = null): int
    {
        try {
            $config = $this->getDeviceConfig();
            $daysInactive = $daysInactive ?? $config['cleanup_days'];
            $cutoffDate = now()->subDays($daysInactive);

            $deleted = TrustedDevice::where('last_used_at', '<', $cutoffDate)->delete();

            Log::info('Inactive trusted devices cleaned up', [
                'file' => 'DeviceManagementService.php',
                'method' => 'cleanupInactiveDevices',
                'days_inactive' => $daysInactive,
                'devices_deleted' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - cleanupInactiveDevices() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'cleanupInactiveDevices',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Generate a unique device ID based on request characteristics.
     *
     * @param Request $request
     * @return string
     * @throws \Exception
     */
    private function generateDeviceId(Request $request): string
    {
        try {
            $components = [
                $request->userAgent() ?? 'unknown',
                $request->header('Accept-Language', 'unknown'),
                $request->header('Accept-Encoding', 'unknown'),
                $request->header('Accept', 'unknown'),
            ];

            $deviceString = implode('|', $components);
            return hash('sha256', $deviceString);
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - generateDeviceId() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'generateDeviceId',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Parse device information from request.
     *
     * @param Request $request
     * @return array
     * @throws \Exception
     */
    private function parseDeviceInfo(Request $request): array
    {
        try {
            $userAgent = $request->userAgent() ?? '';

            return [
                'browser' => $this->parseBrowser($userAgent),
                'platform' => $this->parsePlatform($userAgent),
                'user_agent' => $userAgent,
            ];
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - parseDeviceInfo() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'parseDeviceInfo',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Parse browser information from user agent.
     *
     * @param string $userAgent
     * @return string
     */
    private function parseBrowser(string $userAgent): string
    {
        if (stripos($userAgent, 'Edg/') !== false) return 'Edge';
        if (stripos($userAgent, 'Chrome') !== false) return 'Chrome';
        if (stripos($userAgent, 'Firefox') !== false) return 'Firefox';
        if (stripos($userAgent, 'Safari') !== false && stripos($userAgent, 'Chrome') === false) return 'Safari';
        if (stripos($userAgent, 'Opera') !== false || stripos($userAgent, 'OPR') !== false) return 'Opera';

        return 'Unknown';
    }

    /**
     * Parse platform information from user agent.
     *
     * @param string $userAgent
     * @return string
     */
    private function parsePlatform(string $userAgent): string
    {
        if (stripos($userAgent, 'Windows NT') !== false) return 'Windows';
        if (stripos($userAgent, 'Macintosh') !== false || stripos($userAgent, 'Mac OS') !== false) return 'macOS';
        if (stripos($userAgent, 'X11') !== false || stripos($userAgent, 'Linux') !== false) return 'Linux';
        if (stripos($userAgent, 'iPhone') !== false) return 'iOS';
        if (stripos($userAgent, 'iPad') !== false) return 'iPadOS';
        if (stripos($userAgent, 'Android') !== false) return 'Android';

        return 'Unknown';
    }

    /**
     * Generate a friendly device name.
     *
     * @param array $deviceInfo
     * @return string
     */
    private function generateDeviceName(array $deviceInfo): string
    {
        return $deviceInfo['browser'] . ' on ' . $deviceInfo['platform'];
    }

    /**
     * Enforce trusted device limits for a user.
     *
     * @param User $user
     * @return void
     * @throws \Exception
     */
    private function enforceDeviceLimits(User $user): void
    {
        try {
            $config = $this->getDeviceConfig();
            $deviceCount = TrustedDevice::where('user_id', $user->id)->count();

            if ($deviceCount >= $config['max_trusted_devices']) {
                // Remove oldest devices to make room
                $oldestDevices = TrustedDevice::where('user_id', $user->id)
                    ->orderBy('last_used_at', 'asc')
                    ->limit($deviceCount - $config['max_trusted_devices'] + 1)
                    ->delete();

                Log::info('Device limit enforced - oldest devices removed', [
                    'file' => 'DeviceManagementService.php',
                    'method' => 'enforceDeviceLimits',
                    'user_id' => $user->id,
                    'devices_removed' => $oldestDevices
                ]);
            }
        } catch (\Exception $e) {
            Log::error('DeviceManagementService.php - enforceDeviceLimits() method error: ' . $e->getMessage(), [
                'file' => 'DeviceManagementService.php',
                'method' => 'enforceDeviceLimits',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}

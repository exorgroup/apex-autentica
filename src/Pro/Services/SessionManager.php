<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Service class for advanced session management including device tracking, location data, concurrent sessions, and security monitoring
 * File Location: apex/autentica/src/Pro/Services/SessionManager.php
 */

namespace Apex\Autentica\Pro\Services;

use App\Models\User;
use Apex\Autentica\Pro\Models\Session;
use Apex\Autentica\Pro\Models\TrustedDevice;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Http\Request;

class SessionManager
{
    /**
     * Get session configuration values
     *
     * @return array
     */
    private function getSessionConfig(): array
    {
        return [
            'max_concurrent' => config('autentica_pro.sessions.max_concurrent', 5),
            'cleanup_hours' => config('autentica_pro.sessions.cleanup_hours', 24),
            'location_timeout' => config('autentica_pro.sessions.location_timeout', 5),
        ];
    }

    /**
     * Create a new session record for a user.
     *
     * @param User $user
     * @param Request $request
     * @return Session
     * @throws \Exception
     */
    public function createSession(User $user, Request $request): Session
    {
        try {
            $deviceId = $this->generateDeviceId($request);
            $locationData = $this->getLocationData($request->ip());

            // Check session limits
            $this->enforceSessionLimits($user);

            $session = Session::create([
                'user_id' => $user->id,
                'session_id' => session()->getId(),
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'device_id' => $deviceId,
                'location' => $locationData,
                'last_activity' => now(),
            ]);

            // Update trusted device if applicable
            $this->updateTrustedDevice($user, $deviceId, $request);

            Log::info('Session created successfully', [
                'file' => 'SessionManager.php',
                'method' => 'createSession',
                'user_id' => $user->id,
                'session_id' => $session->id,
                'device_id' => $deviceId
            ]);

            return $session;
        } catch (\Exception $e) {
            Log::error('SessionManager.php - createSession() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'createSession',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Update session activity.
     *
     * @param string $sessionId
     * @param string|null $ipAddress
     * @return bool
     * @throws \Exception
     */
    public function updateActivity(string $sessionId, ?string $ipAddress = null): bool
    {
        try {
            $updateData = ['last_activity' => now()];

            if ($ipAddress) {
                $updateData['ip_address'] = $ipAddress;
            }

            $updated = Session::where('session_id', $sessionId)
                ->update($updateData);

            if ($updated) {
                Log::info('Session activity updated', [
                    'file' => 'SessionManager.php',
                    'method' => 'updateActivity',
                    'session_id' => $sessionId
                ]);
            }

            return $updated > 0;
        } catch (\Exception $e) {
            Log::error('SessionManager.php - updateActivity() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'updateActivity',
                'session_id' => $sessionId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * End a specific session.
     *
     * @param User $user
     * @param int $sessionId
     * @return bool
     * @throws \Exception
     */
    public function endSession(User $user, int $sessionId): bool
    {
        try {
            $deleted = Session::where('id', $sessionId)
                ->where('user_id', $user->id)
                ->delete();

            Log::info('Session ended', [
                'file' => 'SessionManager.php',
                'method' => 'endSession',
                'user_id' => $user->id,
                'session_id' => $sessionId,
                'deleted' => $deleted > 0
            ]);

            return $deleted > 0;
        } catch (\Exception $e) {
            Log::error('SessionManager.php - endSession() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'endSession',
                'user_id' => $user->id,
                'session_id' => $sessionId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * End all sessions for a user except the current one.
     *
     * @param User $user
     * @param string|null $exceptSessionId
     * @return int Number of sessions ended
     * @throws \Exception
     */
    public function endAllOtherSessions(User $user, ?string $exceptSessionId = null): int
    {
        try {
            $query = Session::where('user_id', $user->id);

            if ($exceptSessionId) {
                $query->where('session_id', '!=', $exceptSessionId);
            }

            $deleted = $query->delete();

            Log::info('All other sessions ended', [
                'file' => 'SessionManager.php',
                'method' => 'endAllOtherSessions',
                'user_id' => $user->id,
                'sessions_ended' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('SessionManager.php - endAllOtherSessions() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'endAllOtherSessions',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get active sessions for a user.
     *
     * @param User $user
     * @param int $limit
     * @return \Illuminate\Database\Eloquent\Collection
     * @throws \Exception
     */
    public function getActiveSessions(User $user, int $limit = 50): \Illuminate\Database\Eloquent\Collection
    {
        try {
            $sessions = Session::where('user_id', $user->id)
                ->orderBy('last_activity', 'desc')
                ->limit($limit)
                ->get();

            Log::info('Active sessions retrieved', [
                'file' => 'SessionManager.php',
                'method' => 'getActiveSessions',
                'user_id' => $user->id,
                'session_count' => $sessions->count()
            ]);

            return $sessions;
        } catch (\Exception $e) {
            Log::error('SessionManager.php - getActiveSessions() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'getActiveSessions',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Clean up expired sessions.
     *
     * @param int $hoursInactive Hours of inactivity before session is considered expired
     * @return int Number of sessions cleaned up
     * @throws \Exception
     */
    public function cleanupExpiredSessions(?int $hoursInactive = null): int
    {
        try {
            $config = $this->getSessionConfig();
            $hoursInactive = $hoursInactive ?? $config['cleanup_hours'];
            $cutoff = now()->subHours($hoursInactive);

            $deleted = Session::where('last_activity', '<', $cutoff)->delete();

            Log::info('Expired sessions cleaned up', [
                'file' => 'SessionManager.php',
                'method' => 'cleanupExpiredSessions',
                'hours_inactive' => $hoursInactive,
                'sessions_deleted' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('SessionManager.php - cleanupExpiredSessions() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'cleanupExpiredSessions',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if device is trusted for the user.
     *
     * @param User $user
     * @param string $deviceId
     * @return bool
     * @throws \Exception
     */
    public function isDeviceTrusted(User $user, string $deviceId): bool
    {
        try {
            return TrustedDevice::where('user_id', $user->id)
                ->where('device_id', $deviceId)
                ->exists();
        } catch (\Exception $e) {
            Log::error('SessionManager.php - isDeviceTrusted() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'isDeviceTrusted',
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get session statistics for a user.
     *
     * @param User $user
     * @return array
     * @throws \Exception
     */
    public function getSessionStats(User $user): array
    {
        try {
            $totalSessions = Session::where('user_id', $user->id)->count();
            $activeSessions = Session::where('user_id', $user->id)
                ->where('last_activity', '>', now()->subHours(1))
                ->count();
            $uniqueDevices = Session::where('user_id', $user->id)
                ->distinct('device_id')
                ->count('device_id');
            $lastActivity = Session::where('user_id', $user->id)
                ->orderBy('last_activity', 'desc')
                ->value('last_activity');

            $stats = [
                'total_sessions' => $totalSessions,
                'active_sessions' => $activeSessions,
                'unique_devices' => $uniqueDevices,
                'last_activity' => $lastActivity,
            ];

            Log::info('Session statistics retrieved', [
                'file' => 'SessionManager.php',
                'method' => 'getSessionStats',
                'user_id' => $user->id,
                'stats' => $stats
            ]);

            return $stats;
        } catch (\Exception $e) {
            Log::error('SessionManager.php - getSessionStats() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'getSessionStats',
                'user_id' => $user->id,
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
            ];

            $deviceString = implode('|', $components);
            return hash('sha256', $deviceString);
        } catch (\Exception $e) {
            Log::error('SessionManager.php - generateDeviceId() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'generateDeviceId',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get geographical location data for an IP address.
     *
     * @param string|null $ipAddress
     * @return array|null
     * @throws \Exception
     */
    private function getLocationData(?string $ipAddress): ?array
    {
        try {
            if (!$ipAddress || $ipAddress === '127.0.0.1' || $ipAddress === '::1') {
                return [
                    'country' => 'Unknown',
                    'city' => 'Unknown',
                    'region' => 'Unknown',
                ];
            }

            // Use a free IP geolocation service (in production, consider paid services)
            $config = $this->getSessionConfig();
            $response = Http::timeout($config['location_timeout'])->get("http://ip-api.com/json/{$ipAddress}");

            if ($response->successful()) {
                $data = $response->json();

                if ($data['status'] === 'success') {
                    return [
                        'country' => $data['country'] ?? 'Unknown',
                        'country_code' => $data['countryCode'] ?? null,
                        'region' => $data['regionName'] ?? 'Unknown',
                        'city' => $data['city'] ?? 'Unknown',
                        'timezone' => $data['timezone'] ?? null,
                        'isp' => $data['isp'] ?? null,
                    ];
                }
            }

            return [
                'country' => 'Unknown',
                'city' => 'Unknown',
                'region' => 'Unknown',
            ];
        } catch (\Exception $e) {
            Log::error('SessionManager.php - getLocationData() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'getLocationData',
                'ip_address' => $ipAddress,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            // Return default on error
            return [
                'country' => 'Unknown',
                'city' => 'Unknown',
                'region' => 'Unknown',
            ];
        }
    }

    /**
     * Enforce concurrent session limits for a user.
     *
     * @param User $user
     * @return void
     * @throws \Exception
     */
    private function enforceSessionLimits(User $user): void
    {
        try {
            $config = $this->getSessionConfig();
            $sessionCount = Session::where('user_id', $user->id)->count();

            if ($sessionCount >= $config['max_concurrent']) {
                // Remove oldest sessions to make room
                $oldestSessions = Session::where('user_id', $user->id)
                    ->orderBy('last_activity', 'asc')
                    ->limit($sessionCount - $config['max_concurrent'] + 1)
                    ->delete();

                Log::info('Session limit enforced - oldest sessions removed', [
                    'file' => 'SessionManager.php',
                    'method' => 'enforceSessionLimits',
                    'user_id' => $user->id,
                    'sessions_removed' => $oldestSessions
                ]);
            }
        } catch (\Exception $e) {
            Log::error('SessionManager.php - enforceSessionLimits() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'enforceSessionLimits',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Update or create trusted device record.
     *
     * @param User $user
     * @param string $deviceId
     * @param Request $request
     * @return void
     * @throws \Exception
     */
    private function updateTrustedDevice(User $user, string $deviceId, Request $request): void
    {
        try {
            // Parse user agent for device info
            $userAgent = $request->userAgent() ?? '';
            $browser = $this->parseBrowser($userAgent);
            $platform = $this->parsePlatform($userAgent);

            TrustedDevice::updateOrCreate(
                [
                    'user_id' => $user->id,
                    'device_id' => $deviceId,
                ],
                [
                    'browser' => $browser,
                    'platform' => $platform,
                    'ip_address' => $request->ip(),
                    'last_used_at' => now(),
                ]
            );

            Log::info('Trusted device updated', [
                'file' => 'SessionManager.php',
                'method' => 'updateTrustedDevice',
                'user_id' => $user->id,
                'device_id' => $deviceId
            ]);
        } catch (\Exception $e) {
            Log::error('SessionManager.php - updateTrustedDevice() method error: ' . $e->getMessage(), [
                'file' => 'SessionManager.php',
                'method' => 'updateTrustedDevice',
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            // Don't throw here as this is not critical
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
        if (stripos($userAgent, 'Chrome') !== false) return 'Chrome';
        if (stripos($userAgent, 'Firefox') !== false) return 'Firefox';
        if (stripos($userAgent, 'Safari') !== false) return 'Safari';
        if (stripos($userAgent, 'Edge') !== false) return 'Edge';
        if (stripos($userAgent, 'Opera') !== false) return 'Opera';

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
        if (stripos($userAgent, 'Windows') !== false) return 'Windows';
        if (stripos($userAgent, 'Macintosh') !== false) return 'macOS';
        if (stripos($userAgent, 'Linux') !== false) return 'Linux';
        if (stripos($userAgent, 'iPhone') !== false) return 'iOS';
        if (stripos($userAgent, 'Android') !== false) return 'Android';

        return 'Unknown';
    }
}

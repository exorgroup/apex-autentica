<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Permission caching service for optimizing permission checks. Manages cache
 *              warming, invalidation, and provides cache statistics.
 * URL: apex/autentica/src/Core/Services/PermissionCache.php
 */

namespace Apex\Autentica\Core\Services;

use App\Models\User;
use Apex\Autentica\Core\Models\Group;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Collection;

class PermissionCache
{
    /**
     * Warm the permission cache for all active users.
     *
     * @param int|null $limit
     * @return int Number of users cached
     */
    public function warmUserCache(?int $limit = null): int
    {
        try {
            $query = User::query();

            if ($limit) {
                $query->limit($limit);
            }

            $count = 0;
            $query->chunk(100, function ($users) use (&$count) {
                foreach ($users as $user) {
                    $this->warmUserPermissions($user);
                    $count++;
                }
            });

            return $count;
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - warmUserCache() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Warm the permission cache for a specific user.
     *
     * @param User $user
     * @return array
     */
    public function warmUserPermissions(User $user): array
    {
        try {
            // This will trigger cache generation
            return $user->getCachedPermissions();
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - warmUserPermissions() method error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Clear permission cache for a specific user.
     *
     * @param User $user
     * @return bool
     */
    public function clearUserCache(User $user): bool
    {
        try {
            $user->clearPermissionCache();
            return true;
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - clearUserCache() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Clear permission cache for a specific group and all its users.
     *
     * @param Group $group
     * @return int Number of caches cleared
     */
    public function clearGroupCache(Group $group): int
    {
        try {
            $count = 0;

            // Clear cache for all users in the group
            foreach ($group->users as $user) {
                if ($this->clearUserCache($user)) {
                    $count++;
                }
            }

            return $count;
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - clearGroupCache() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Clear all permission caches.
     *
     * @return bool
     */
    public function clearAllCache(): bool
    {
        try {
            $tag = config('permissions.cache.tag', 'autentica_permissions');

            if (Cache::getStore() instanceof \Illuminate\Cache\TaggableStore) {
                Cache::tags([$tag])->flush();
            } else {
                // Fallback: clear individual user caches
                $prefix = config('permissions.cache.prefix', 'autentica_permissions');
                User::chunk(100, function ($users) use ($prefix) {
                    foreach ($users as $user) {
                        Cache::forget("{$prefix}.User.{$user->id}");
                    }
                });
            }

            return true;
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - clearAllCache() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get cache statistics.
     *
     * @return array
     */
    public function getStatistics(): array
    {
        try {
            $stats = [
                'enabled' => config('permissions.cache.enabled', true),
                'ttl' => config('permissions.cache.ttl', 3600),
                'prefix' => config('permissions.cache.prefix', 'autentica_permissions'),
                'tag' => config('permissions.cache.tag', 'autentica_permissions'),
                'cached_users' => 0,
                'cache_size' => 0,
                'supports_tags' => Cache::getStore() instanceof \Illuminate\Cache\TaggableStore,
            ];

            if (!$stats['enabled']) {
                return $stats;
            }

            // Count cached users (this is an approximation)
            $prefix = $stats['prefix'];
            $userCount = 0;

            // Only check a sample to avoid performance issues
            User::limit(100)->get()->each(function ($user) use ($prefix, &$userCount) {
                $cacheKey = "{$prefix}.User.{$user->id}";
                if (Cache::has($cacheKey)) {
                    $userCount++;
                }
            });

            $stats['cached_users'] = $userCount;

            return $stats;
        } catch (\Exception $e) {
            // Only log if it's not a tagging error
            if (!str_contains($e->getMessage(), 'does not support tagging')) {
                Log::error('PermissionCache.php - getStatistics() method error: ' . $e->getMessage());
            }
            return [
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Refresh cache for users in specific groups.
     *
     * @param array $groupIds
     * @return int Number of users refreshed
     */
    public function refreshGroupUsersCache(array $groupIds): int
    {
        try {
            $count = 0;

            $users = User::whereHas('groups', function ($query) use ($groupIds) {
                $query->whereIn('id', $groupIds);
            })->get();

            foreach ($users as $user) {
                $user->clearPermissionCache();
                $this->warmUserPermissions($user);
                $count++;
            }

            return $count;
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - refreshGroupUsersCache() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Check if a user's permissions are cached.
     *
     * @param User $user
     * @return bool
     */
    public function isCached(User $user): bool
    {
        try {
            if (!config('permissions.cache.enabled', true)) {
                return false;
            }

            $prefix = config('permissions.cache.prefix', 'autentica_permissions');
            $cacheKey = "{$prefix}.User.{$user->id}";

            return Cache::has($cacheKey);
        } catch (\Exception $e) {
            // Only log if it's not a tagging error
            if (!str_contains($e->getMessage(), 'does not support tagging')) {
                Log::error('PermissionCache.php - isCached() method error: ' . $e->getMessage());
            }
            return false;
        }
    }

    /**
     * Get the remaining TTL for a user's cache.
     *
     * @param User $user
     * @return int|null Seconds remaining, null if not cached
     */
    public function getTTL(User $user): ?int
    {
        try {
            if (!$this->isCached($user)) {
                return null;
            }

            // This is an approximation as Laravel doesn't provide direct TTL access
            // Return configured TTL as we can't get the actual remaining time
            return config('permissions.cache.ttl', 3600);
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - getTTL() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Warm cache for users with recent activity.
     *
     * @param int $minutes
     * @return int Number of users cached
     */
    public function warmRecentlyActiveUsers(int $minutes = 30): int
    {
        try {
            $count = 0;

            $users = User::whereHas('securityEvents', function ($query) use ($minutes) {
                $query->where('created_at', '>=', now()->subMinutes($minutes));
            })->get();

            foreach ($users as $user) {
                $this->warmUserPermissions($user);
                $count++;
            }

            return $count;
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - warmRecentlyActiveUsers() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Clear cache for users who haven't been active.
     *
     * @param int $days
     * @return int Number of caches cleared
     */
    public function clearInactiveUsersCache(int $days = 30): int
    {
        try {
            $count = 0;

            $users = User::whereDoesntHave('securityEvents', function ($query) use ($days) {
                $query->where('created_at', '>=', now()->subDays($days));
            })->get();

            foreach ($users as $user) {
                if ($this->clearUserCache($user)) {
                    $count++;
                }
            }

            return $count;
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - clearInactiveUsersCache() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get cache memory usage estimate.
     *
     * @return array
     */
    public function getMemoryUsage(): array
    {
        try {
            $totalSize = 0;
            $userCount = 0;
            $sampleSize = 0;

            // Sample a few users to estimate average cache size
            User::limit(10)->get()->each(function ($user) use (&$sampleSize, &$userCount) {
                if ($this->isCached($user)) {
                    $permissions = $user->getCachedPermissions();
                    $sampleSize += strlen(serialize($permissions));
                    $userCount++;
                }
            });

            $averageSize = $userCount > 0 ? $sampleSize / $userCount : 0;
            $totalUsers = $this->getStatistics()['cached_users'];
            $estimatedTotal = $averageSize * $totalUsers;

            return [
                'average_size_bytes' => $averageSize,
                'estimated_total_bytes' => $estimatedTotal,
                'estimated_total_mb' => round($estimatedTotal / 1024 / 1024, 2),
                'cached_users' => $totalUsers,
            ];
        } catch (\Exception $e) {
            Log::error('PermissionCache.php - getMemoryUsage() method error: ' . $e->getMessage());
            return [
                'error' => $e->getMessage(),
            ];
        }
    }
}

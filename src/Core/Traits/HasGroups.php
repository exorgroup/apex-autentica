<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: HasGroups trait for users. Provides group membership management functionality
 *              including adding, removing, and checking group memberships.
 * URL: apex/autentica/src/Core/Traits/HasGroups.php
 */

namespace Apex\Autentica\Core\Traits;

use Apex\Autentica\Core\Models\Group;
use Illuminate\Support\Facades\Log;

trait HasGroups
{
    /**
     * Get all groups this user belongs to.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function groups()
    {
        try {
            return $this->belongsToMany(Group::class, 'Au10_user_groups', 'user_id', 'group_id')
                ->withTimestamps()
                ->withPivot('signature');
        } catch (\Exception $e) {
            Log::error('HasGroups.php - groups() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Check if the user belongs to a specific group.
     *
     * @param string|int|Group $group Group name, ID, or instance
     * @return bool
     */
    public function belongsToGroup($group): bool
    {
        try {
            if ($group instanceof Group) {
                return $this->groups()->where('group_id', $group->id)->exists();
            }

            if (is_numeric($group)) {
                return $this->groups()->where('group_id', $group)->exists();
            }

            return $this->groups()->where('name', $group)->exists();
        } catch (\Exception $e) {
            Log::error('HasGroups.php - belongsToGroup() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if the user belongs to any of the specified groups.
     *
     * @param array $groups Array of group names, IDs, or instances
     * @return bool
     */
    public function belongsToAnyGroup(array $groups): bool
    {
        try {
            foreach ($groups as $group) {
                if ($this->belongsToGroup($group)) {
                    return true;
                }
            }
            return false;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - belongsToAnyGroup() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if the user belongs to all of the specified groups.
     *
     * @param array $groups Array of group names, IDs, or instances
     * @return bool
     */
    public function belongsToAllGroups(array $groups): bool
    {
        try {
            foreach ($groups as $group) {
                if (!$this->belongsToGroup($group)) {
                    return false;
                }
            }
            return true;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - belongsToAllGroups() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Add the user to a group.
     *
     * @param string|int|Group $group Group name, ID, or instance
     * @return bool
     */
    public function joinGroup($group): bool
    {
        try {
            if (!($group instanceof Group)) {
                if (is_numeric($group)) {
                    $group = Group::find($group);
                } else {
                    $group = Group::where('name', $group)->first();
                }
            }

            if (!$group) {
                return false;
            }

            if (!$this->belongsToGroup($group)) {
                $this->groups()->attach($group->id, [
                    'signature' => hash('sha512', $this->id . $group->id . now()->toDateTimeString())
                ]);
                $this->clearPermissionCacheIfAvailable();
            }

            return true;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - joinGroup() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Remove the user from a group.
     *
     * @param string|int|Group $group Group name, ID, or instance
     * @return bool
     */
    public function leaveGroup($group): bool
    {
        try {
            if (!($group instanceof Group)) {
                if (is_numeric($group)) {
                    $group = Group::find($group);
                } else {
                    $group = Group::where('name', $group)->first();
                }
            }

            if (!$group) {
                return false;
            }

            $result = $this->groups()->detach($group->id) > 0;

            if ($result) {
                $this->clearPermissionCacheIfAvailable();
            }

            return $result;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - leaveGroup() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Add the user to multiple groups.
     *
     * @param array $groups Array of group names, IDs, or instances
     * @return int Number of groups successfully joined
     */
    public function joinGroups(array $groups): int
    {
        try {
            $joined = 0;

            foreach ($groups as $group) {
                if ($this->joinGroup($group)) {
                    $joined++;
                }
            }

            return $joined;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - joinGroups() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Remove the user from multiple groups.
     *
     * @param array $groups Array of group names, IDs, or instances
     * @return int Number of groups successfully left
     */
    public function leaveGroups(array $groups): int
    {
        try {
            $left = 0;

            foreach ($groups as $group) {
                if ($this->leaveGroup($group)) {
                    $left++;
                }
            }

            return $left;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - leaveGroups() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Sync the user's groups.
     *
     * @param array $groups Array of group IDs or names
     * @return array
     */
    public function syncGroups(array $groups): array
    {
        try {
            $groupIds = [];

            foreach ($groups as $group) {
                if (is_numeric($group)) {
                    $groupIds[] = $group;
                } else {
                    $groupModel = Group::where('name', $group)->first();
                    if ($groupModel) {
                        $groupIds[] = $groupModel->id;
                    }
                }
            }

            $result = $this->groups()->sync(array_combine($groupIds, array_map(function ($id) {
                return ['signature' => hash('sha512', $this->id . $id . now()->toDateTimeString())];
            }, $groupIds)));
            $this->clearPermissionCacheIfAvailable();

            return $result;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - syncGroups() method error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get all group names for this user.
     *
     * @return array
     */
    public function getGroupNames(): array
    {
        try {
            return $this->groups()->pluck('name')->toArray();
        } catch (\Exception $e) {
            Log::error('HasGroups.php - getGroupNames() method error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get all group IDs for this user.
     *
     * @return array
     */
    public function getGroupIds(): array
    {
        try {
            return $this->groups()->pluck('id')->toArray();
        } catch (\Exception $e) {
            Log::error('HasGroups.php - getGroupIds() method error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Check if the user has any groups.
     *
     * @return bool
     */
    public function hasGroups(): bool
    {
        try {
            return $this->groups()->exists();
        } catch (\Exception $e) {
            Log::error('HasGroups.php - hasGroups() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get the primary group for this user (first group joined).
     *
     * @return Group|null
     */
    public function getPrimaryGroup(): ?Group
    {
        try {
            return $this->groups()->orderBy('Au10_user_groups.created_at')->first();
        } catch (\Exception $e) {
            Log::error('HasGroups.php - getPrimaryGroup() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Clear permission cache if the trait has it.
     *
     * @return void
     */
    protected function clearPermissionCacheIfAvailable(): void
    {
        if (method_exists($this, 'clearPermissionCache')) {
            $this->clearPermissionCache();
        }
    }
}

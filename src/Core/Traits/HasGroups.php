<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: HasGroups trait for users. Provides group membership management functionality
 *              including adding, removing, and checking group memberships.
 * URL: exorgroup/apex-autentica/src/Core/Traits/HasGroups.php
 */

namespace Apex\Autentica\Core\Traits;

use Apex\Autentica\Core\Exceptions\AutenticaException;
use Apex\Autentica\Core\Models\Group;
use Apex\Signature\SignatureService;
use Illuminate\Support\Facades\DB;
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
            return $this->belongsToMany(Group::class, 'au10_group_user', 'user_id', 'group_id')
                ->withTimestamps()
                ->withPivot('assigned_at', 'assigned_by', 'signature');
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
        // Keep the original argument: resolveGroup() returns null on a miss, so reporting
        // $group after reassigning it would name nothing.
        $resolved = $this->resolveGroup($group);

        if (! $resolved) {
            throw AutenticaException::groupNotFound($group);
        }

        $group = $resolved;

        if ($this->belongsToGroup($group)) {
            return true;
        }

        try {
            $this->groups()->attach($group->id, $this->groupPivotAttributes($group->id));
            $this->clearPermissionCacheIfAvailable();

            return true;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - joinGroup() method error: ' . $e->getMessage());

            // Deliberately not returning false: the caller cannot tell that apart from
            // "already a member", and would carry on believing the user has access.
            throw AutenticaException::membershipWriteFailed('joinGroup', $e);
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
        $resolved = $this->resolveGroup($group);

        if (! $resolved) {
            throw AutenticaException::groupNotFound($group);
        }

        $group = $resolved;

        try {
            $removed = $this->groups()->detach($group->id) > 0;

            if ($removed) {
                $this->clearPermissionCacheIfAvailable();
            }

            return $removed;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - leaveGroup() method error: ' . $e->getMessage());

            throw AutenticaException::membershipWriteFailed('leaveGroup', $e);
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
        $joined = 0;

        foreach ($groups as $group) {
            // joinGroup() throws on failure, which is what we want: silently counting a
            // failed join would report success the caller cannot act on.
            if ($this->joinGroup($group)) {
                $joined++;
            }
        }

        return $joined;
    }

    /**
     * Remove the user from multiple groups.
     *
     * @param array $groups Array of group names, IDs, or instances
     * @return int Number of groups successfully left
     */
    public function leaveGroups(array $groups): int
    {
        $left = 0;

        foreach ($groups as $group) {
            if ($this->leaveGroup($group)) {
                $left++;
            }
        }

        return $left;
    }

    /**
     * Sync the user's groups.
     *
     * @param array $groups Array of group IDs or names
     * @return array
     */
    public function syncGroups(array $groups): array
    {
        $groupIds = [];

        foreach ($groups as $group) {
            $resolved = $this->resolveGroup($group);

            if (! $resolved) {
                throw AutenticaException::groupNotFound($group);
            }

            $groupIds[] = $resolved->id;
        }

        try {
            // sync() detaches before it attaches. Without a transaction, an attach that fails
            // leaves the user in NO group at all - no permissions, and nothing to say why.
            // The transaction turns that into "no change", plus a thrown exception.
            $result = DB::transaction(function () use ($groupIds) {
                return $this->groups()->sync(array_combine(
                    $groupIds,
                    array_map(fn ($id) => $this->groupPivotAttributes($id), $groupIds)
                ));
            });

            $this->clearPermissionCacheIfAvailable();

            return $result;
        } catch (\Exception $e) {
            Log::error('HasGroups.php - syncGroups() method error: ' . $e->getMessage());

            throw AutenticaException::membershipWriteFailed('syncGroups', $e);
        }
    }

    /**
     * Resolve a group from a name, id or instance.
     *
     * @param string|int|Group $group
     * @return \Apex\Autentica\Core\Models\Group|null
     */
    protected function resolveGroup($group): ?Group
    {
        if ($group instanceof Group) {
            return $group;
        }

        if (is_numeric($group)) {
            return Group::find($group);
        }

        return Group::where('name', $group)->first();
    }

    /**
     * The pivot columns written when a user joins a group.
     *
     * Declared once. This was previously hand-written separately in joinGroup() and
     * syncGroups(), and both wrote a 'signature' column that au10_group_user does not have -
     * the insert threw, the catch swallowed it, and users silently ended up in no group.
     *
     * Anything added here must exist on the pivot table AND be listed in withPivot() on
     * groups(). autentica:doctor checks exactly that.
     *
     * @return array<string, mixed>
     */
    protected function groupPivotAttributes(?int $groupId = null): array
    {
        $attributes = [
            'assigned_at' => now(),
            // Who did this, when there is a signed-in user to attribute it to.
            'assigned_by' => auth()->id(),
        ];

        // Signed over stable, stored values only - never the current time - so the signature
        // can be recomputed from the row months later. Empty while signing is switched off.
        $attributes['signature'] = app(SignatureService::class)->generate([
            'user_id' => $this->getKey(),
            'group_id' => $groupId,
            'assigned_at' => $attributes['assigned_at']->toDateTimeString(),
            'assigned_by' => $attributes['assigned_by'],
        ], 'autentica');

        return $attributes;
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
            return $this->groups()->orderBy('au10_group_user.created_at')->first();
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

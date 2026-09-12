<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Group model for managing user groups in the authentication system. Handles single-level
 *              groups (Core package) with relationships to users and permissions.
 * URL: exorgroup/apex-autentica/src/Core/Models/Group.php
 */

namespace Apex\Autentica\Core\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Apex\Autentica\Core\Traits\Signable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Foundation\Auth\User;
use Apex\Autentica\Core\Support\Autentica;

class Group extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'au10_groups';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'name',
        'description',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    /**
     * Get the users that belong to this group.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function users(): BelongsToMany
    {
        try {
            return $this->belongsToMany(Autentica::userModel(), 'au10_group_user', 'group_id', 'user_id')
                ->withTimestamps()
                ->withPivot('assigned_at', 'assigned_by');
        } catch (\Exception $e) {
            Log::error('Group.php - users() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Get all permissions for this group.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany
     */
    public function permissions(): MorphMany
    {
        try {
            return $this->morphMany(Permission::class, 'permissionable');
        } catch (\Exception $e) {
            Log::error('Group.php - permissions() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Check if the group has a specific permission.
     *
     * @param string $resource The resource identifier
     * @param string $action The action to check (create, read, update, delete, print, history)
     * @return bool
     */
    public function hasPermission(string $resource, string $action): bool
    {
        try {
            $permission = $this->permissions()
                ->whereHas('systemResource', function ($query) use ($resource) {
                    $query->where('identifier', $resource);
                })
                ->first();

            if (!$permission) {
                return false;
            }

            $column = 'can_' . $action;

            // Check standard permissions
            if (isset($permission->$column) && $permission->$column) {
                return true;
            }

            // Check custom permissions
            if ($permission->custom_permissions) {
                $customPermissions = explode(',', $permission->custom_permissions);
                return in_array($action, $customPermissions);
            }

            return false;
        } catch (\Exception $e) {
            Log::error('Group.php - hasPermission() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Grant a permission to this group.
     *
     * @param \Apex\Autentica\Core\Models\SystemResource $resource
     * @param array $permissions
     * @return \Apex\Autentica\Core\Models\Permission
     */
    public function grantPermission(SystemResource $resource, array $permissions): Permission
    {
        try {
            // Delegated rather than repeated. createFor() carries two things this method used
            // to get wrong: it writes custom_permissions even when empty, so re-granting
            // without customs actually clears the old ones; and it upserts withTrashed(),
            // which the unique index on (holder, resource) requires — that index ignores
            // deleted_at, so a revoked row still occupies the slot and a plain insert would
            // collide, leaving the pair permanently un-grantable.
            return Permission::createFor($this, $resource, $permissions);
        } catch (\Exception $e) {
            Log::error('Group.php - grantPermission() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Copy every permission another group holds onto this one.
     *
     * A snapshot, not a link: later changes to the source do not follow. That is what makes
     * "create a group like this one" safe to offer — the new group is editable from the moment
     * it exists, and nobody has to reason about which of its permissions are really somebody
     * else's.
     *
     * @param Group $source The group to copy from
     * @return int How many resources were copied
     * @throws \Exception
     */
    public function copyPermissionsFrom(Group $source): int
    {
        try {
            if ($source->is($this)) {
                return 0;
            }

            $copied = 0;

            DB::transaction(function () use ($source, &$copied) {
                foreach ($source->permissions()->with('systemResource')->get() as $permission) {
                    $resource = $permission->systemResource;

                    // A permission whose resource has been deleted has nothing to grant.
                    if (! $resource) {
                        continue;
                    }

                    $actions = $permission->getAllowedActions();

                    if (empty($actions)) {
                        continue;
                    }

                    Permission::createFor($this, $resource, $actions);
                    $copied++;
                }
            });

            Log::info('Group permissions copied', [
                'file' => 'Group.php',
                'method' => 'copyPermissionsFrom',
                'from_group_id' => $source->id,
                'to_group_id' => $this->id,
                'resources_copied' => $copied,
            ]);

            return $copied;
        } catch (\Exception $e) {
            Log::error('Group.php - copyPermissionsFrom() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Revoke a permission from this group.
     *
     * @param \Apex\Autentica\Core\Models\SystemResource $resource
     * @return bool
     */
    public function revokePermission(SystemResource $resource): bool
    {
        try {
            return $this->permissions()
                ->where('system_resource_id', $resource->id)
                ->delete() > 0;
        } catch (\Exception $e) {
            Log::error('Group.php - revokePermission() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Add a user to this group.
     *
     * @param \Illuminate\Foundation\Auth\User $user
     * @return void
     */
    public function addUser(User $user): void
    {
        try {
            if (!$this->users()->where('user_id', $user->id)->exists()) {
                $this->users()->attach($user->id);
            }
        } catch (\Exception $e) {
            Log::error('Group.php - addUser() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Remove a user from this group.
     *
     * @param \Illuminate\Foundation\Auth\User $user
     * @return void
     */
    public function removeUser(User $user): void
    {
        try {
            $this->users()->detach($user->id);
        } catch (\Exception $e) {
            Log::error('Group.php - removeUser() method error: ' . $e->getMessage());
            throw $e;
        }
    }
}

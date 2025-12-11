<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Permission model for managing access rights. Links users/groups to system resources
 *              with specific permissions (CRUD + custom).
 * URL: apex/autentica/src/Core/Models/Permission.php
 */

namespace Apex\Autentica\Core\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Apex\Autentica\Core\Traits\Signable;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class Permission extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'Au10_permissions';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'permissionable_type',
        'permissionable_id',
        'system_resource_id',
        'can_create',
        'can_read',
        'can_update',
        'can_delete',
        'can_print',
        'can_history',
        'custom_permissions',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'permissionable_id' => 'integer',
        'system_resource_id' => 'integer',
        'can_create' => 'boolean',
        'can_read' => 'boolean',
        'can_update' => 'boolean',
        'can_delete' => 'boolean',
        'can_print' => 'boolean',
        'can_history' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    /**
     * The "booted" method of the model.
     *
     * @return void
     */
    protected static function booted(): void
    {
        try {
            // Clear permission cache when permissions are modified
            static::saved(function ($permission) {
                $permission->clearCache();
            });

            static::deleted(function ($permission) {
                $permission->clearCache();
            });
        } catch (\Exception $e) {
            Log::error('Permission.php - booted() method error: ' . $e->getMessage());
        }
    }

    /**
     * Get the owning permissionable model (User or Group).
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo
     */
    public function permissionable(): MorphTo
    {
        try {
            return $this->morphTo();
        } catch (\Exception $e) {
            Log::error('Permission.php - permissionable() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Get the system resource this permission applies to.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function systemResource(): BelongsTo
    {
        try {
            return $this->belongsTo(SystemResource::class, 'system_resource_id');
        } catch (\Exception $e) {
            Log::error('Permission.php - systemResource() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Check if this permission grants a specific action.
     *
     * @param string $action
     * @return bool
     */
    public function allows(string $action): bool
    {
        try {
            // Check standard permissions
            $column = 'can_' . $action;
            if (property_exists($this, $column) && $this->$column) {
                return true;
            }

            // Check custom permissions
            if ($this->custom_permissions) {
                $customPermissions = explode(',', $this->custom_permissions);
                return in_array($action, array_map('trim', $customPermissions));
            }

            return false;
        } catch (\Exception $e) {
            Log::error('Permission.php - allows() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get all allowed actions for this permission.
     *
     * @return array
     */
    public function getAllowedActions(): array
    {
        try {
            $actions = [];

            // Standard actions
            foreach (['create', 'read', 'update', 'delete', 'print', 'history'] as $action) {
                if ($this->{'can_' . $action}) {
                    $actions[] = $action;
                }
            }

            // Custom actions
            if ($this->custom_permissions) {
                $customActions = array_map('trim', explode(',', $this->custom_permissions));
                $actions = array_merge($actions, $customActions);
            }

            return array_unique($actions);
        } catch (\Exception $e) {
            Log::error('Permission.php - getAllowedActions() method error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Grant specific actions to this permission.
     *
     * @param array|string $actions
     * @return bool
     */
    public function grant($actions): bool
    {
        try {
            $actions = is_array($actions) ? $actions : [$actions];

            foreach ($actions as $action) {
                $column = 'can_' . $action;

                if (property_exists($this, $column)) {
                    $this->$column = true;
                } else {
                    // Add to custom permissions
                    $customPermissions = $this->custom_permissions ? explode(',', $this->custom_permissions) : [];
                    if (!in_array($action, $customPermissions)) {
                        $customPermissions[] = $action;
                        $this->custom_permissions = implode(',', $customPermissions);
                    }
                }
            }

            return $this->save();
        } catch (\Exception $e) {
            Log::error('Permission.php - grant() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Revoke specific actions from this permission.
     *
     * @param array|string $actions
     * @return bool
     */
    public function revoke($actions): bool
    {
        try {
            $actions = is_array($actions) ? $actions : [$actions];

            foreach ($actions as $action) {
                $column = 'can_' . $action;

                if (property_exists($this, $column)) {
                    $this->$column = false;
                } else {
                    // Remove from custom permissions
                    if ($this->custom_permissions) {
                        $customPermissions = explode(',', $this->custom_permissions);
                        $customPermissions = array_diff($customPermissions, [$action]);
                        $this->custom_permissions = empty($customPermissions) ? null : implode(',', $customPermissions);
                    }
                }
            }

            return $this->save();
        } catch (\Exception $e) {
            Log::error('Permission.php - revoke() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Clear permission cache for the associated user/group.
     *
     * @return void
     */
    protected function clearCache(): void
    {
        try {
            if (config('permissions.cache.enabled', true)) {
                $cacheKey = config('permissions.cache.prefix', 'autentica_permissions');

                if ($this->permissionable_type === 'App\Models\User') {
                    Cache::forget("{$cacheKey}.User.{$this->permissionable_id}");
                } else {
                    // Without tags, we need to clear cache for each user in the group
                    if ($this->permissionable && method_exists($this->permissionable, 'users')) {
                        foreach ($this->permissionable->users as $user) {
                            Cache::forget("{$cacheKey}.User.{$user->id}");
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            // Only log if it's not a tagging error
            if (!str_contains($e->getMessage(), 'does not support tagging')) {
                Log::error('Permission.php - clearCache() method error: ' . $e->getMessage());
            }
        }
    }

    /**
     * Create a permission set for a user or group.
     *
     * @param Model $permissionable
     * @param SystemResource $resource
     * @param array $permissions
     * @return Permission
     */
    public static function createFor($permissionable, SystemResource $resource, array $permissions): Permission
    {
        try {
            $data = [
                'permissionable_type' => get_class($permissionable),
                'permissionable_id' => $permissionable->id,
                'system_resource_id' => $resource->id,
            ];

            // Set standard permissions
            foreach (['create', 'read', 'update', 'delete', 'print', 'history'] as $action) {
                $data['can_' . $action] = in_array($action, $permissions);
            }

            // Handle custom permissions
            $standardActions = ['create', 'read', 'update', 'delete', 'print', 'history'];
            $customPermissions = array_diff($permissions, $standardActions);
            if (!empty($customPermissions)) {
                $data['custom_permissions'] = implode(',', $customPermissions);
            }

            return static::create($data);
        } catch (\Exception $e) {
            Log::error('Permission.php - createFor() method error: ' . $e->getMessage());
            throw $e;
        }
    }
}

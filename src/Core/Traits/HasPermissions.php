<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: HasPermissions trait for users and groups. Provides permission checking,
 *              granting, and revoking functionality with caching support.
 * URL: apex/autentica/src/Core/Traits/HasPermissions.php
 */

namespace Apex\Autentica\Core\Traits;

use Apex\Autentica\Core\Models\Permission;
use Apex\Autentica\Core\Models\SystemResource;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

trait HasPermissions
{
    /**
     * Get all permissions for this model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany
     */
    public function permissions()
    {
        try {
            return $this->morphMany(Permission::class, 'permissionable');
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - permissions() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Check if the model has a specific permission.
     *
     * @param string $resource Resource identifier
     * @param string|array $actions Action(s) to check
     * @return bool
     */
    public function hasPermission(string $resource, $actions): bool
    {
        try {
            $actions = is_array($actions) ? $actions : [$actions];
            $permissions = $this->getCachedPermissions();

            if (!isset($permissions[$resource])) {
                return false;
            }

            foreach ($actions as $action) {
                // Check standard permissions
                $column = 'can_' . $action;
                if (isset($permissions[$resource][$column]) && $permissions[$resource][$column]) {
                    return true;
                }

                // Check custom permissions
                if (isset($permissions[$resource]['custom_permissions'])) {
                    $customPerms = explode(',', $permissions[$resource]['custom_permissions']);
                    if (in_array($action, array_map('trim', $customPerms))) {
                        return true;
                    }
                }
            }

            return false;
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - hasPermission() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if the model has any of the specified permissions.
     *
     * @param string $resource Resource identifier
     * @param array $actions Actions to check
     * @return bool
     */
    public function hasAnyPermission(string $resource, array $actions): bool
    {
        try {
            foreach ($actions as $action) {
                if ($this->hasPermission($resource, $action)) {
                    return true;
                }
            }
            return false;
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - hasAnyPermission() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if the model has all of the specified permissions.
     *
     * @param string $resource Resource identifier
     * @param array $actions Actions to check
     * @return bool
     */
    public function hasAllPermissions(string $resource, array $actions): bool
    {
        try {
            foreach ($actions as $action) {
                if (!$this->hasPermission($resource, $action)) {
                    return false;
                }
            }
            return true;
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - hasAllPermissions() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get cached permissions for this model.
     *
     * @return array
     */
    public function getCachedPermissions(): array
    {
        try {
            if (!config('permissions.cache.enabled', true)) {
                return $this->buildPermissionsArray();
            }

            $cacheKey = $this->getPermissionCacheKey();
            $ttl = config('permissions.cache.ttl', 3600);

            return Cache::remember($cacheKey, $ttl, function () {
                return $this->buildPermissionsArray();
            });
        } catch (\Exception $e) {
            // If there's a cache error, just build permissions without caching
            if (!str_contains($e->getMessage(), 'does not support tagging')) {
                Log::error('HasPermissions.php - getCachedPermissions() method error: ' . $e->getMessage());
            }
            return $this->buildPermissionsArray();
        }
    }

    /**
     * Build permissions array for caching.
     *
     * @return array
     */
    protected function buildPermissionsArray(): array
    {
        try {
            $permissions = [];

            // Get direct permissions
            $directPermissions = $this->permissions()
                ->with('systemResource')
                ->get();

            foreach ($directPermissions as $permission) {
                if ($permission->systemResource) {
                    $resourceId = $permission->systemResource->identifier;
                    $permissions[$resourceId] = [
                        'can_create' => $permission->can_create,
                        'can_read' => $permission->can_read,
                        'can_update' => $permission->can_update,
                        'can_delete' => $permission->can_delete,
                        'can_print' => $permission->can_print,
                        'can_history' => $permission->can_history,
                        'custom_permissions' => $permission->custom_permissions,
                    ];
                }
            }

            // If this is a User model, also get group permissions
            if ($this instanceof \App\Models\User && method_exists($this, 'groups')) {
                $this->load('groups.permissions.systemResource');

                foreach ($this->groups as $group) {
                    $groupPermissions = $group->permissions()
                        ->with('systemResource')
                        ->get();

                    foreach ($groupPermissions as $permission) {
                        if ($permission->systemResource) {
                            $resourceId = $permission->systemResource->identifier;

                            // If user doesn't have direct permission, use group permission
                            if (!isset($permissions[$resourceId])) {
                                $permissions[$resourceId] = [
                                    'can_create' => $permission->can_create,
                                    'can_read' => $permission->can_read,
                                    'can_update' => $permission->can_update,
                                    'can_delete' => $permission->can_delete,
                                    'can_print' => $permission->can_print,
                                    'can_history' => $permission->can_history,
                                    'custom_permissions' => $permission->custom_permissions,
                                ];
                            } elseif (config('permissions.inheritance.most_permissive_wins', true)) {
                                // Merge permissions - most permissive wins
                                $permissions[$resourceId]['can_create'] = $permissions[$resourceId]['can_create'] || $permission->can_create;
                                $permissions[$resourceId]['can_read'] = $permissions[$resourceId]['can_read'] || $permission->can_read;
                                $permissions[$resourceId]['can_update'] = $permissions[$resourceId]['can_update'] || $permission->can_update;
                                $permissions[$resourceId]['can_delete'] = $permissions[$resourceId]['can_delete'] || $permission->can_delete;
                                $permissions[$resourceId]['can_print'] = $permissions[$resourceId]['can_print'] || $permission->can_print;
                                $permissions[$resourceId]['can_history'] = $permissions[$resourceId]['can_history'] || $permission->can_history;

                                // Merge custom permissions
                                if ($permission->custom_permissions) {
                                    $existing = $permissions[$resourceId]['custom_permissions'] ? explode(',', $permissions[$resourceId]['custom_permissions']) : [];
                                    $new = explode(',', $permission->custom_permissions);
                                    $merged = array_unique(array_merge($existing, $new));
                                    $permissions[$resourceId]['custom_permissions'] = implode(',', $merged);
                                }
                            }
                        }
                    }
                }
            }

            return $permissions;
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - buildPermissionsArray() method error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Clear permission cache for this model.
     *
     * @return void
     */
    public function clearPermissionCache(): void
    {
        try {
            if (config('permissions.cache.enabled', true)) {
                Cache::forget($this->getPermissionCacheKey());
            }
        } catch (\Exception $e) {
            // Only log if it's not a tagging error
            if (!str_contains($e->getMessage(), 'does not support tagging')) {
                Log::error('HasPermissions.php - clearPermissionCache() method error: ' . $e->getMessage());
            }
        }
    }

    /**
     * Get the cache key for permissions.
     *
     * @return string
     */
    protected function getPermissionCacheKey(): string
    {
        try {
            $prefix = config('permissions.cache.prefix', 'autentica_permissions');
            $type = class_basename($this);
            return "{$prefix}.{$type}.{$this->id}";
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - getPermissionCacheKey() method error: ' . $e->getMessage());
            return 'autentica_permissions.unknown.' . uniqid();
        }
    }

    /**
     * Grant permissions to this model.
     *
     * @param string|SystemResource $resource
     * @param array $permissions
     * @return Permission
     */
    public function grantPermission($resource, array $permissions): Permission
    {
        try {
            if (is_string($resource)) {
                $resource = SystemResource::findByIdentifier($resource);
                if (!$resource) {
                    throw new \InvalidArgumentException("System resource not found: {$resource}");
                }
            }

            $permission = Permission::createFor($this, $resource, $permissions);
            $this->clearPermissionCache();

            return $permission;
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - grantPermission() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Revoke permissions from this model.
     *
     * @param string|SystemResource $resource
     * @param array|null $permissions Specific permissions to revoke, or null to revoke all
     * @return bool
     */
    public function revokePermission($resource, ?array $permissions = null): bool
    {
        try {
            if (is_string($resource)) {
                $resource = SystemResource::findByIdentifier($resource);
                if (!$resource) {
                    return false;
                }
            }

            $permission = $this->permissions()
                ->where('system_resource_id', $resource->id)
                ->first();

            if (!$permission) {
                return false;
            }

            if ($permissions === null) {
                // Revoke all permissions
                $result = $permission->delete();
            } else {
                // Revoke specific permissions
                $result = $permission->revoke($permissions);
            }

            $this->clearPermissionCache();
            return $result;
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - revokePermission() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Sync permissions for a resource.
     *
     * @param string|SystemResource $resource
     * @param array $permissions
     * @return Permission
     */
    public function syncPermissions($resource, array $permissions): Permission
    {
        try {
            if (is_string($resource)) {
                $resource = SystemResource::findByIdentifier($resource);
                if (!$resource) {
                    throw new \InvalidArgumentException("System resource not found: {$resource}");
                }
            }

            $data = [
                'system_resource_id' => $resource->id,
            ];

            // Set all standard permissions
            foreach (['create', 'read', 'update', 'delete', 'print', 'history'] as $action) {
                $data['can_' . $action] = in_array($action, $permissions);
            }

            // Handle custom permissions
            $standardActions = ['create', 'read', 'update', 'delete', 'print', 'history'];
            $customPermissions = array_diff($permissions, $standardActions);
            $data['custom_permissions'] = !empty($customPermissions) ? implode(',', $customPermissions) : null;

            $permission = $this->permissions()->updateOrCreate(
                ['system_resource_id' => $resource->id],
                $data
            );

            $this->clearPermissionCache();
            return $permission;
        } catch (\Exception $e) {
            Log::error('HasPermissions.php - syncPermissions() method error: ' . $e->getMessage());
            throw $e;
        }
    }
}

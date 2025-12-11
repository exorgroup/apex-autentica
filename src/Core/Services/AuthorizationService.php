<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Core authorization service handling permission checks, resource management,
 *              and access control logic for users and groups.
 * URL: apex/autentica/src/Core/Services/AuthorizationService.php
 */

namespace Apex\Autentica\Core\Services;

use App\Models\User;
use Apex\Autentica\Core\Models\Group;
use Apex\Autentica\Core\Models\SystemResource;
use Apex\Autentica\Core\Models\Permission;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Collection;

class AuthorizationService
{
    /**
     * Check if a user has permission for a resource.
     *
     * @param User $user
     * @param string $resource
     * @param string|array $actions
     * @return bool
     */
    public function userCan(User $user, string $resource, $actions): bool
    {
        try {
            return $user->hasPermission($resource, $actions);
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - userCan() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if a user has any of the specified permissions.
     *
     * @param User $user
     * @param string $resource
     * @param array $actions
     * @return bool
     */
    public function userCanAny(User $user, string $resource, array $actions): bool
    {
        try {
            return $user->hasAnyPermission($resource, $actions);
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - userCanAny() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if a user has all of the specified permissions.
     *
     * @param User $user
     * @param string $resource
     * @param array $actions
     * @return bool
     */
    public function userCanAll(User $user, string $resource, array $actions): bool
    {
        try {
            return $user->hasAllPermissions($resource, $actions);
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - userCanAll() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Grant permissions to a user or group.
     *
     * @param User|Group $model
     * @param string $resource
     * @param array $permissions
     * @return Permission|null
     */
    public function grant($model, string $resource, array $permissions): ?Permission
    {
        try {
            $systemResource = SystemResource::findByIdentifier($resource);
            if (!$systemResource) {
                Log::warning("AuthorizationService.php - grant() resource not found: {$resource}");
                return null;
            }

            $permission = $model->grantPermission($systemResource, $permissions);

            // Log the permission change
            if ($model instanceof User) {
                $model->logPermissionChange('granted', $resource, $permissions);
            }

            return $permission;
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - grant() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Revoke permissions from a user or group.
     *
     * @param User|Group $model
     * @param string $resource
     * @param array|null $permissions
     * @return bool
     */
    public function revoke($model, string $resource, ?array $permissions = null): bool
    {
        try {
            $result = $model->revokePermission($resource, $permissions);

            // Log the permission change
            if ($result && $model instanceof User) {
                $model->logPermissionChange('revoked', $resource, $permissions ?? ['all']);
            }

            return $result;
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - revoke() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Sync permissions for a user or group.
     *
     * @param User|Group $model
     * @param string $resource
     * @param array $permissions
     * @return Permission|null
     */
    public function sync($model, string $resource, array $permissions): ?Permission
    {
        try {
            $permission = $model->syncPermissions($resource, $permissions);

            // Log the permission change
            if ($model instanceof User) {
                $model->logPermissionChange('synced', $resource, $permissions);
            }

            return $permission;
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - sync() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get all permissions for a user.
     *
     * @param User $user
     * @return array
     */
    public function getUserPermissions(User $user): array
    {
        try {
            return $user->getCachedPermissions();
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - getUserPermissions() method error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get all users with a specific permission.
     *
     * @param string $resource
     * @param string $action
     * @return Collection
     */
    public function getUsersWithPermission(string $resource, string $action): Collection
    {
        try {
            $systemResource = SystemResource::findByIdentifier($resource);
            if (!$systemResource) {
                return collect();
            }

            return $systemResource->getUsersWithPermission($action);
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - getUsersWithPermission() method error: ' . $e->getMessage());
            return collect();
        }
    }

    /**
     * Create or update a system resource.
     *
     * @param array $data
     * @return SystemResource|null
     */
    public function createResource(array $data): ?SystemResource
    {
        try {
            return SystemResource::createOrUpdate($data);
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - createResource() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Delete a system resource and all associated permissions.
     *
     * @param string $identifier
     * @return bool
     */
    public function deleteResource(string $identifier): bool
    {
        try {
            $resource = SystemResource::findByIdentifier($identifier);
            if (!$resource) {
                return false;
            }

            // Delete all permissions for this resource
            Permission::where('system_resource_id', $resource->id)->delete();

            // Delete the resource
            return $resource->delete();
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - deleteResource() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get hierarchical resource structure.
     *
     * @return Collection
     */
    public function getResourceHierarchy(): Collection
    {
        try {
            return SystemResource::getHierarchical();
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - getResourceHierarchy() method error: ' . $e->getMessage());
            return collect();
        }
    }

    /**
     * Copy permissions from one user to another.
     *
     * @param User $sourceUser
     * @param User $targetUser
     * @param array|null $resourceFilter
     * @return int Number of permissions copied
     */
    public function copyUserPermissions(User $sourceUser, User $targetUser, ?array $resourceFilter = null): int
    {
        try {
            $count = 0;
            $sourcePermissions = $sourceUser->permissions()->with('systemResource')->get();

            foreach ($sourcePermissions as $permission) {
                if ($resourceFilter && !in_array($permission->systemResource->identifier, $resourceFilter)) {
                    continue;
                }

                $data = [
                    'system_resource_id' => $permission->system_resource_id,
                    'can_create' => $permission->can_create,
                    'can_read' => $permission->can_read,
                    'can_update' => $permission->can_update,
                    'can_delete' => $permission->can_delete,
                    'can_print' => $permission->can_print,
                    'can_history' => $permission->can_history,
                    'custom_permissions' => $permission->custom_permissions,
                ];

                $targetUser->permissions()->updateOrCreate(
                    ['system_resource_id' => $permission->system_resource_id],
                    $data
                );

                $count++;
            }

            $targetUser->clearPermissionCache();
            $targetUser->logSecurityEvent('permissions_copied', [
                'source_user_id' => $sourceUser->id,
                'permissions_count' => $count,
            ]);

            return $count;
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - copyUserPermissions() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Copy permissions from one group to another.
     *
     * @param Group $sourceGroup
     * @param Group $targetGroup
     * @param array|null $resourceFilter
     * @return int Number of permissions copied
     */
    public function copyGroupPermissions(Group $sourceGroup, Group $targetGroup, ?array $resourceFilter = null): int
    {
        try {
            $count = 0;
            $sourcePermissions = $sourceGroup->permissions()->with('systemResource')->get();

            foreach ($sourcePermissions as $permission) {
                if ($resourceFilter && !in_array($permission->systemResource->identifier, $resourceFilter)) {
                    continue;
                }

                $data = [
                    'system_resource_id' => $permission->system_resource_id,
                    'can_create' => $permission->can_create,
                    'can_read' => $permission->can_read,
                    'can_update' => $permission->can_update,
                    'can_delete' => $permission->can_delete,
                    'can_print' => $permission->can_print,
                    'can_history' => $permission->can_history,
                    'custom_permissions' => $permission->custom_permissions,
                ];

                $targetGroup->permissions()->updateOrCreate(
                    ['system_resource_id' => $permission->system_resource_id],
                    $data
                );

                $count++;
            }

            // Clear cache for all users in the target group
            foreach ($targetGroup->users as $user) {
                $user->clearPermissionCache();
            }

            return $count;
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - copyGroupPermissions() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Bulk update permissions.
     *
     * @param array $updates Array of permission updates
     * @return int Number of permissions updated
     */
    public function bulkUpdatePermissions(array $updates): int
    {
        try {
            $count = 0;

            foreach ($updates as $update) {
                $model = $update['model'] ?? null;
                $resource = $update['resource'] ?? null;
                $permissions = $update['permissions'] ?? [];

                if (!$model || !$resource) {
                    continue;
                }

                if ($this->sync($model, $resource, $permissions)) {
                    $count++;
                }
            }

            // Clear all permission caches
            Cache::tags(config('permissions.cache.tag', 'autentica_permissions'))->flush();

            return $count;
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - bulkUpdatePermissions() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get permission matrix for display.
     *
     * @param Collection $models Users or Groups
     * @param Collection|null $resources
     * @return array
     */
    public function getPermissionMatrix(Collection $models, ?Collection $resources = null): array
    {
        try {
            if (!$resources) {
                $resources = SystemResource::all();
            }

            $matrix = [];

            foreach ($models as $model) {
                $modelData = [
                    'id' => $model->id,
                    'name' => $model->name ?? $model->email,
                    'type' => class_basename($model),
                    'permissions' => [],
                ];

                foreach ($resources as $resource) {
                    $permission = $model->permissions()
                        ->where('system_resource_id', $resource->id)
                        ->first();

                    $modelData['permissions'][$resource->identifier] = [
                        'can_create' => $permission->can_create ?? false,
                        'can_read' => $permission->can_read ?? false,
                        'can_update' => $permission->can_update ?? false,
                        'can_delete' => $permission->can_delete ?? false,
                        'can_print' => $permission->can_print ?? false,
                        'can_history' => $permission->can_history ?? false,
                        'custom' => $permission->custom_permissions ?? '',
                    ];
                }

                $matrix[] = $modelData;
            }

            return $matrix;
        } catch (\Exception $e) {
            Log::error('AuthorizationService.php - getPermissionMatrix() method error: ' . $e->getMessage());
            return [];
        }
    }
}

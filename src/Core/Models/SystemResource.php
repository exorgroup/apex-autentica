<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: SystemResource model for managing protected resources in the authorization system.
 *              Represents models, functions, and modules that can have permissions assigned.
 * URL: apex/autentica/src/Core/Models/SystemResource.php
 */

namespace Apex\Autentica\Core\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Apex\Autentica\Core\Traits\Signable;
use Illuminate\Support\Facades\Log;
use App\Models\User;

class SystemResource extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'Au10_system_resources';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'parent_id',
        'name',
        'identifier',
        'type',
        'description',
        'menu_order',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'parent_id' => 'integer',
        'menu_order' => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    /**
     * Get all permissions for this resource.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function permissions(): HasMany
    {
        try {
            return $this->hasMany(Permission::class, 'system_resource_id');
        } catch (\Exception $e) {
            Log::error('SystemResource.php - permissions() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Get the parent resource.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function parent()
    {
        try {
            return $this->belongsTo(SystemResource::class, 'parent_id');
        } catch (\Exception $e) {
            Log::error('SystemResource.php - parent() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Get the child resources.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function children(): HasMany
    {
        try {
            return $this->hasMany(SystemResource::class, 'parent_id')
                ->orderBy('menu_order')
                ->orderBy('name');
        } catch (\Exception $e) {
            Log::error('SystemResource.php - children() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Find a resource by its identifier.
     *
     * @param string $identifier
     * @return \Apex\Autentica\Core\Models\SystemResource|null
     */
    public static function findByIdentifier(string $identifier): ?SystemResource
    {
        try {
            return static::where('identifier', $identifier)->first();
        } catch (\Exception $e) {
            Log::error('SystemResource.php - findByIdentifier() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Create or update a resource.
     *
     * @param array $attributes
     * @return \Apex\Autentica\Core\Models\SystemResource
     */
    public static function createOrUpdate(array $attributes): SystemResource
    {
        try {
            return static::updateOrCreate(
                ['identifier' => $attributes['identifier']],
                $attributes
            );
        } catch (\Exception $e) {
            Log::error('SystemResource.php - createOrUpdate() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Get all resources of a specific type.
     *
     * @param string $type
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public static function byType(string $type)
    {
        try {
            return static::where('type', $type)
                ->orderBy('menu_order')
                ->orderBy('name')
                ->get();
        } catch (\Exception $e) {
            Log::error('SystemResource.php - byType() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Get resources in hierarchical structure.
     *
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public static function getHierarchical()
    {
        try {
            return static::whereNull('parent_id')
                ->with('children')
                ->orderBy('menu_order')
                ->orderBy('name')
                ->get();
        } catch (\Exception $e) {
            Log::error('SystemResource.php - getHierarchical() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Check if any user or group has permission for this resource.
     *
     * @param string $action
     * @return bool
     */
    public function hasAnyPermission(string $action): bool
    {
        try {
            $column = 'can_' . $action;

            return $this->permissions()
                ->where($column, true)
                ->exists();
        } catch (\Exception $e) {
            Log::error('SystemResource.php - hasAnyPermission() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get all users who have a specific permission for this resource.
     *
     * @param string $action
     * @return \Illuminate\Support\Collection
     */
    public function getUsersWithPermission(string $action)
    {
        try {
            $column = 'can_' . $action;

            $userIds = $this->permissions()
                ->where('permissionable_type', 'App\Models\User')
                ->where($column, true)
                ->pluck('permissionable_id');

            $groupUserIds = $this->permissions()
                ->where('permissionable_type', Group::class)
                ->where($column, true)
                ->with('permissionable.users')
                ->get()
                ->pluck('permissionable.users')
                ->flatten()
                ->pluck('id');

            return User::whereIn('id', $userIds->merge($groupUserIds)->unique())->get();
        } catch (\Exception $e) {
            Log::error('SystemResource.php - getUsersWithPermission() method error: ' . $e->getMessage());
            throw $e;
        }
    }
}

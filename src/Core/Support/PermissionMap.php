<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Compacts a user's effective permissions into two flat maps small enough to ship
 *              to the browser on every request, for the JS can() helper to read.
 * URL: exorgroup/apex-autentica/src/Core/Support/PermissionMap.php
 */

namespace Apex\Autentica\Core\Support;

use Illuminate\Support\Facades\Log;

class PermissionMap
{
    /**
     * The six standard actions, in the order their letters appear.
     *
     * @var array<string, string>
     */
    public const ACTIONS = [
        'can_create'  => 'c',
        'can_read'    => 'r',
        'can_update'  => 'u',
        'can_delete'  => 'd',
        'can_print'   => 'p',
        'can_history' => 'h',
    ];

    /**
     * Build both maps for a user.
     *
     * Returns:
     *   [
     *     'can'       => ['events' => 'cru', 'reports' => 'rp'],
     *     'canCustom' => ['events' => ['approve_hero']],
     *   ]
     *
     * Resources the user has no access to at all are omitted rather than sent as empty
     * strings, which keeps the payload proportional to what a user can actually do.
     *
     * @param mixed $user A user model using the HasPermissions trait, or null.
     * @return array{can: array<string, string>, canCustom: array<string, array<int, string>>}
     */
    public static function for($user): array
    {
        try {
            if (! $user || ! method_exists($user, 'getCachedPermissions')) {
                return ['can' => [], 'canCustom' => []];
            }

            return static::compact($user->getCachedPermissions());
        } catch (\Exception $e) {
            Log::error('PermissionMap.php - for() method error: ' . $e->getMessage());

            // Deny by default: a failure here must not hand out access it cannot prove.
            return ['can' => [], 'canCustom' => []];
        }
    }

    /**
     * Compact the verbose permission array into the two wire maps.
     *
     * @param array $permissions Output of HasPermissions::getCachedPermissions()
     * @return array{can: array<string, string>, canCustom: array<string, array<int, string>>}
     */
    public static function compact(array $permissions): array
    {
        try {
            $can = [];
            $canCustom = [];
            $separator = config('autentica.permissions.custom.separator', ',');

            foreach ($permissions as $identifier => $flags) {
                if (! is_array($flags)) {
                    continue;
                }

                $letters = '';
                foreach (static::ACTIONS as $key => $letter) {
                    if (! empty($flags[$key])) {
                        $letters .= $letter;
                    }
                }

                if ($letters !== '') {
                    $can[$identifier] = $letters;
                }

                $custom = $flags['custom_permissions'] ?? null;
                if (is_string($custom) && trim($custom) !== '') {
                    $list = array_values(array_filter(array_map('trim', explode($separator, $custom))));
                    if ($list) {
                        $canCustom[$identifier] = $list;
                    }
                }
            }

            return ['can' => $can, 'canCustom' => $canCustom];
        } catch (\Exception $e) {
            Log::error('PermissionMap.php - compact() method error: ' . $e->getMessage());

            return ['can' => [], 'canCustom' => []];
        }
    }
}

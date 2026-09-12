<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Raised when a write to group membership or permissions fails.
 * URL: exorgroup/apex-autentica/src/Core/Exceptions/AutenticaException.php
 */

namespace Apex\Autentica\Core\Exceptions;

use RuntimeException;

/**
 * Autentica reads and writes fail differently, on purpose.
 *
 * Reads — belongsToGroup(), hasPermission() — keep returning false and logging. Denying is
 * the safe answer, and a permission check that threw on a transient database blip would take
 * the whole application down.
 *
 * Writes throw this. Returning false from joinGroup() reads as "already a member" rather than
 * "the write failed", and nobody can recover from a schema mismatch anyway. A membership
 * change that silently does nothing leaves someone with no access and nothing to explain it.
 */
class AutenticaException extends RuntimeException
{
    /**
     * A group could not be found by name or id.
     *
     * @param mixed $group
     * @return static
     */
    public static function groupNotFound(mixed $group): static
    {
        return new static(sprintf(
            'Autentica: no group matching "%s". Group names are case-sensitive; run autentica:doctor to list them.',
            is_scalar($group) ? (string) $group : get_debug_type($group)
        ));
    }

    /**
     * A membership write failed.
     *
     * @param string $operation
     * @param \Throwable $previous
     * @return static
     */
    public static function membershipWriteFailed(string $operation, \Throwable $previous): static
    {
        return new static(
            "Autentica: {$operation} failed — {$previous->getMessage()}. "
            . 'Run "php artisan autentica:doctor" to check the schema matches the models.',
            0,
            $previous
        );
    }

    /**
     * A permission write failed.
     *
     * @param string $operation
     * @param \Throwable $previous
     * @return static
     */
    public static function permissionWriteFailed(string $operation, \Throwable $previous): static
    {
        return new static(
            "Autentica: {$operation} failed — {$previous->getMessage()}. "
            . 'Run "php artisan autentica:doctor" to check the schema matches the models.',
            0,
            $previous
        );
    }
}

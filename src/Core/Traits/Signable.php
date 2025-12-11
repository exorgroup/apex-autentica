<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Signable trait for automatic SHA512 signature generation on model save.
 *              Ensures data integrity by creating a hash of model attributes.
 * URL: apex/autentica/src/Core/Traits/Signable.php
 */

namespace Apex\Autentica\Core\Traits;

use Illuminate\Support\Facades\Log;

trait Signable
{
    /**
     * Boot the signable trait for a model.
     *
     * @return void
     */
    public static function bootSignable(): void
    {
        try {
            // Generate signature before creating (but after the model is about to be saved)
            static::creating(function ($model) {
                if (!$model->signature) {
                    $model->generateSignature();
                }
            });

            // Generate signature after creating to include the ID
            static::created(function ($model) {
                $model->generateSignature();
                $model->saveQuietly(); // Save without triggering events
            });

            // Regenerate signature before updating
            static::updating(function ($model) {
                $model->generateSignature();
            });
        } catch (\Exception $e) {
            Log::error('Signable.php - bootSignable() method error: ' . $e->getMessage());
        }
    }

    /**
     * Generate SHA512 signature for the model.
     *
     * @return void
     */
    public function generateSignature(): void
    {
        try {
            // Get all attributes except signature itself and timestamps
            $attributes = $this->getAttributes();
            unset($attributes['signature']);
            unset($attributes['created_at']);
            unset($attributes['updated_at']);
            unset($attributes['deleted_at']);

            // Sort attributes by key to ensure consistent hashing
            ksort($attributes);

            // Create a string representation of the attributes
            $dataString = json_encode($attributes);

            // Add table name and tenant identifier (if in multi-tenant environment)
            $dataString .= $this->getTable();

            if (function_exists('tenant') && tenant()) {
                $dataString .= tenant()->id;
            }

            // Generate SHA512 hash
            $this->signature = hash('sha512', $dataString);
        } catch (\Exception $e) {
            Log::error('Signable.php - generateSignature() method error: ' . $e->getMessage());
            // Set a default signature to prevent null constraint violations
            $this->signature = hash('sha512', uniqid('error_signature', true));
        }
    }

    /**
     * Verify the signature of the model.
     *
     * @return bool
     */
    public function verifySignature(): bool
    {
        try {
            $currentSignature = $this->signature;
            $this->generateSignature();
            $isValid = $currentSignature === $this->signature;

            // Restore original signature
            $this->signature = $currentSignature;

            return $isValid;
        } catch (\Exception $e) {
            Log::error('Signable.php - verifySignature() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if the model has been tampered with.
     *
     * @return bool
     */
    public function hasValidSignature(): bool
    {
        try {
            return $this->verifySignature();
        } catch (\Exception $e) {
            Log::error('Signable.php - hasValidSignature() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Force regenerate the signature.
     *
     * @return bool
     */
    public function refreshSignature(): bool
    {
        try {
            $this->generateSignature();
            return $this->save();
        } catch (\Exception $e) {
            Log::error('Signable.php - refreshSignature() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get signature metadata.
     *
     * @return array
     */
    public function getSignatureMetadata(): array
    {
        try {
            return [
                'signature' => $this->signature,
                'algorithm' => 'SHA512',
                'is_valid' => $this->hasValidSignature(),
                'generated_at' => $this->updated_at ?? $this->created_at,
            ];
        } catch (\Exception $e) {
            Log::error('Signable.php - getSignatureMetadata() method error: ' . $e->getMessage());
            return [
                'signature' => null,
                'algorithm' => 'SHA512',
                'is_valid' => false,
                'error' => $e->getMessage(),
            ];
        }
    }
}

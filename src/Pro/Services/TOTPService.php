<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Service class for Time-based One-Time Password (TOTP) authentication management including secret generation, QR codes, and verification
 * File Location: apex/autentica/src/Pro/Services/TOTPService.php
 */

namespace Apex\Autentica\Pro\Services;

use App\Models\User;
use Apex\Autentica\Pro\Models\MfaConfig;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

class TOTPService
{
    /**
     * Base32 alphabet for TOTP secret generation (RFC 4648 compliant)
     */
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Get TOTP configuration values
     *
     * @return array
     */
    private function getTotpConfig(): array
    {
        return [
            'period' => config('autentica_pro.totp.period', 30),
            'digits' => config('autentica_pro.totp.digits', 6),
            'algorithm' => config('autentica_pro.totp.algorithm', 'sha1'), // SHA1 required for authenticator app compatibility
            'window' => config('autentica_pro.totp.window', 1),
            'secret_length' => config('autentica_pro.base32.secret_length', 32),
        ];
    }

    /**
     * Generate a new TOTP secret for a user.
     *
     * @param User $user
     * @return string The generated secret
     * @throws \Exception
     */
    public function generateSecret(User $user): string
    {
        try {
            $config = $this->getTotpConfig();
            $secretLength = $config['secret_length'];

            // Generate a random base32 secret
            $secret = '';
            for ($i = 0; $i < $secretLength; $i++) {
                $secret .= self::BASE32_ALPHABET[random_int(0, 31)];
            }

            Log::info('TOTP secret generated successfully', [
                'file' => 'TOTPService.php',
                'method' => 'generateSecret',
                'user_id' => $user->id
            ]);

            return $secret;
        } catch (\Exception $e) {
            Log::error('TOTPService.php - generateSecret() method error: ' . $e->getMessage(), [
                'file' => 'TOTPService.php',
                'method' => 'generateSecret',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Enable TOTP authentication for a user.
     *
     * @param User $user
     * @param string $secret
     * @return MfaConfig
     * @throws \Exception
     */
    public function enableTOTP(User $user, string $secret): MfaConfig
    {
        try {
            // Create or update MFA config
            $mfaConfig = MfaConfig::updateOrCreate(
                [
                    'user_id' => $user->id,
                    'method' => 'totp'
                ],
                [
                    'secret' => Crypt::encryptString($secret),
                    'verified_at' => null // Will be set when user verifies
                ]
            );

            Log::info('TOTP enabled for user', [
                'file' => 'TOTPService.php',
                'method' => 'enableTOTP',
                'user_id' => $user->id,
                'mfa_config_id' => $mfaConfig->id
            ]);

            return $mfaConfig;
        } catch (\Exception $e) {
            Log::error('TOTPService.php - enableTOTP() method error: ' . $e->getMessage(), [
                'file' => 'TOTPService.php',
                'method' => 'enableTOTP',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Verify a TOTP code for a user.
     *
     * @param User $user
     * @param string $code
     * @param bool $markAsVerified Whether to mark the TOTP as verified
     * @return bool
     * @throws \Exception
     */
    public function verifyCode(User $user, string $code, bool $markAsVerified = false): bool
    {
        try {
            $mfaConfig = MfaConfig::where('user_id', $user->id)
                ->where('method', 'totp')
                ->first();

            if (!$mfaConfig || !$mfaConfig->secret) {
                Log::warning('TOTP verification attempted but no config found', [
                    'file' => 'TOTPService.php',
                    'method' => 'verifyCode',
                    'user_id' => $user->id
                ]);
                return false;
            }

            $secret = Crypt::decryptString($mfaConfig->secret);
            $config = $this->getTotpConfig();
            $currentTime = time();
            $window = $config['window'];

            // Check current time and adjacent time windows
            for ($i = -$window; $i <= $window; $i++) {
                $timeStep = intval($currentTime / $config['period']) + $i;
                $expectedCode = $this->generateTOTPCode($secret, $timeStep, $config);

                if (hash_equals($expectedCode, $code)) {
                    if ($markAsVerified) {
                        $mfaConfig->update(['verified_at' => now()]);
                    }

                    Log::info('TOTP code verified successfully', [
                        'file' => 'TOTPService.php',
                        'method' => 'verifyCode',
                        'user_id' => $user->id,
                        'marked_verified' => $markAsVerified
                    ]);

                    return true;
                }
            }

            Log::warning('TOTP code verification failed', [
                'file' => 'TOTPService.php',
                'method' => 'verifyCode',
                'user_id' => $user->id
            ]);

            return false;
        } catch (\Exception $e) {
            Log::error('TOTPService.php - verifyCode() method error: ' . $e->getMessage(), [
                'file' => 'TOTPService.php',
                'method' => 'verifyCode',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Generate a QR code URL for TOTP setup.
     *
     * @param User $user
     * @param string $secret
     * @param string $issuer
     * @return string
     * @throws \Exception
     */
    public function generateQRCodeUrl(User $user, string $secret, ?string $issuer = null): string
    {
        try {
            $config = $this->getTotpConfig();
            $issuer = $issuer ?? config('autentica_pro.totp.issuer', 'APEX Pro');

            $accountName = urlencode($user->email);
            $issuerName = urlencode($issuer);

            $otpUrl = "otpauth://totp/{$issuerName}:{$accountName}?" .
                "secret={$secret}&issuer={$issuerName}&algorithm=" .
                strtoupper($config['algorithm']) .
                "&digits=" . $config['digits'] .
                "&period=" . $config['period'];

            Log::info('QR code URL generated', [
                'file' => 'TOTPService.php',
                'method' => 'generateQRCodeUrl',
                'user_id' => $user->id
            ]);

            return $otpUrl;
        } catch (\Exception $e) {
            Log::error('TOTPService.php - generateQRCodeUrl() method error: ' . $e->getMessage(), [
                'file' => 'TOTPService.php',
                'method' => 'generateQRCodeUrl',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Disable TOTP authentication for a user.
     *
     * @param User $user
     * @return bool
     * @throws \Exception
     */
    public function disableTOTP(User $user): bool
    {
        try {
            $deleted = MfaConfig::where('user_id', $user->id)
                ->where('method', 'totp')
                ->delete();

            Log::info('TOTP disabled for user', [
                'file' => 'TOTPService.php',
                'method' => 'disableTOTP',
                'user_id' => $user->id,
                'records_deleted' => $deleted
            ]);

            return $deleted > 0;
        } catch (\Exception $e) {
            Log::error('TOTPService.php - disableTOTP() method error: ' . $e->getMessage(), [
                'file' => 'TOTPService.php',
                'method' => 'disableTOTP',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if TOTP is enabled and verified for a user.
     *
     * @param User $user
     * @return bool
     * @throws \Exception
     */
    public function isEnabled(User $user): bool
    {
        try {
            $exists = MfaConfig::where('user_id', $user->id)
                ->where('method', 'totp')
                ->whereNotNull('verified_at')
                ->exists();

            return $exists;
        } catch (\Exception $e) {
            Log::error('TOTPService.php - isEnabled() method error: ' . $e->getMessage(), [
                'file' => 'TOTPService.php',
                'method' => 'isEnabled',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Generate TOTP code for a given secret and time step.
     *
     * @param string $secret
     * @param int $timeStep
     * @param array $config
     * @return string
     * @throws \Exception
     */
    private function generateTOTPCode(string $secret, int $timeStep, array $config): string
    {
        try {
            // Convert base32 secret to binary
            $binarySecret = $this->base32Decode($secret);

            // Pack time step as 64-bit big-endian
            $timeBytes = pack('N*', 0) . pack('N*', $timeStep);

            // Generate HMAC using configured algorithm
            $hash = hash_hmac($config['algorithm'], $timeBytes, $binarySecret, true);

            // Dynamic truncation
            $offset = ord($hash[strlen($hash) - 1]) & 0xf;
            $code = (
                ((ord($hash[$offset]) & 0x7f) << 24) |
                ((ord($hash[$offset + 1]) & 0xff) << 16) |
                ((ord($hash[$offset + 2]) & 0xff) << 8) |
                (ord($hash[$offset + 3]) & 0xff)
            ) % pow(10, $config['digits']);

            return str_pad((string)$code, $config['digits'], '0', STR_PAD_LEFT);
        } catch (\Exception $e) {
            Log::error('TOTPService.php - generateTOTPCode() method error: ' . $e->getMessage(), [
                'file' => 'TOTPService.php',
                'method' => 'generateTOTPCode',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Decode base32 string to binary.
     *
     * @param string $base32
     * @return string
     * @throws \Exception
     */
    private function base32Decode(string $base32): string
    {
        try {
            $base32 = strtoupper($base32);
            $binary = '';
            $bits = '';

            for ($i = 0; $i < strlen($base32); $i++) {
                $char = $base32[$i];
                $pos = strpos(self::BASE32_ALPHABET, $char);
                if ($pos === false) continue;

                $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
            }

            while (strlen($bits) >= 8) {
                $binary .= chr(bindec(substr($bits, 0, 8)));
                $bits = substr($bits, 8);
            }

            return $binary;
        } catch (\Exception $e) {
            Log::error('TOTPService.php - base32Decode() method error: ' . $e->getMessage(), [
                'file' => 'TOTPService.php',
                'method' => 'base32Decode',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}

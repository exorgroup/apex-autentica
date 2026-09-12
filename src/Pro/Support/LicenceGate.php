<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Decides whether Autentica Pro may run. Enforcement is contractual in v1 — this
 *              gate exists so the call sites are already in place when it becomes technical.
 * File Location: exorgroup/apex-autentica/src/Pro/Support/LicenceGate.php
 */

namespace Apex\Autentica\Pro\Support;

use Illuminate\Support\Facades\Log;

class LicenceGate
{
    /**
     * May Autentica Pro run?
     *
     * v1 is legal-only enforcement: Pro is covered by a commercial licence (LICENSE-PRO) and
     * this gate always allows. It is a real call site, not dead code — flipping to a key check
     * later means changing this method alone, with no change anywhere it is called from.
     *
     * @return bool
     */
    public static function allows(): bool
    {
        try {
            // An explicit opt-out is honoured so a deployment can disable Pro wholesale.
            $enabled = config('autentica_pro.enabled', true);

            return (bool) $enabled;
        } catch (\Exception $e) {
            Log::error('LicenceGate.php - allows() method error: ' . $e->getMessage());

            // Fail open: a config read failure must not lock people out of MFA.
            return true;
        }
    }
}

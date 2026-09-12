<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Autentica's tamper-evident signing. A thin bridge onto exorgroup/apex-signature
 *              so the algorithm lives in exactly one place across the APEX packages.
 * URL: exorgroup/apex-autentica/src/Core/Traits/Signable.php
 */

namespace Apex\Autentica\Core\Traits;

use Apex\Signature\Traits\Signable as SharedSignable;

/**
 * Signs Autentica's rows so later tampering shows up.
 *
 * This used to be a self-contained implementation, which drifted from the one in apex-audit:
 * it hashed without a secret, so anyone holding the source could recompute a valid signature
 * for a row they had just altered. The shared package fixes that with a keyed HMAC and is now
 * the single definition of the scheme.
 *
 * Kept as an Autentica trait rather than asking every model to import the shared one, so
 * existing `use Signable;` statements carry on working and every Autentica model signs under
 * the same context automatically.
 *
 * Signing is off unless APEX_SIGNATURE_ENABLED is set, in which case the signature column
 * simply stays empty.
 */
trait Signable
{
    use SharedSignable;

    /**
     * Group every Autentica model under one context.
     *
     * Binding the context into the signature means a signature made for an Autentica row
     * cannot be replayed into another subsystem's table.
     *
     * @return string
     */
    public function signatureContext(): string
    {
        return 'autentica';
    }

    /**
     * Older name for applySignature().
     *
     * Kept so code written against the previous trait keeps working; the shared package
     * settled on applySignature(). Prefer that in new code.
     *
     * @return void
     */
    public function generateSignature(): void
    {
        $this->applySignature();
    }
}

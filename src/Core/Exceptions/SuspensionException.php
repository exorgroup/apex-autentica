<?php

namespace Apex\Autentica\Core\Exceptions;

/**
 * A suspension that must not happen — 0.3.0.
 *
 * Suspending yourself, or the last active member of a protected group: both lock the
 * installation out, one of them with nobody left who could undo it. The message is written for
 * the person who tried.
 */
class SuspensionException extends AutenticaException
{
}

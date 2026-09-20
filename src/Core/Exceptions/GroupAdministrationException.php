<?php

namespace Apex\Autentica\Core\Exceptions;

use RuntimeException;

/**
 * A group administration action that the domain refuses.
 *
 * Not a validation failure and not an authorisation failure: the caller may do this in
 * general, the payload is well formed, and the answer is still no — because carrying it
 * out would leave the installation without administrators.
 *
 * Carries a message written for whoever is looking at the screen, so a UI can show it as
 * it stands.
 */
class GroupAdministrationException extends RuntimeException
{
}

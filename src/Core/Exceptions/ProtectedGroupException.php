<?php

namespace Apex\Autentica\Core\Exceptions;

/**
 * An attempt to rename, delete or re-permission a protected group.
 *
 * The administrators group is matched BY NAME by the host's own checks, so renaming it
 * turns every one of those false — including the check guarding the screen that renamed
 * it. Deleting it, or stripping its permissions, has the same ending by a shorter road.
 */
class ProtectedGroupException extends GroupAdministrationException
{
}

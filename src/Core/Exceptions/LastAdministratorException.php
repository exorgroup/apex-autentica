<?php

namespace Apex\Autentica\Core\Exceptions;

/**
 * Removing the only member of a protected group.
 *
 * Separate from {@see ProtectedGroupException} because the group is not what is being
 * changed — its membership is — and the caller may well be allowed to change membership
 * in general. This is the last-one-out case only.
 */
class LastAdministratorException extends GroupAdministrationException
{
}

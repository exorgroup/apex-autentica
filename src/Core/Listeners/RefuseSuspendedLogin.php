<?php

namespace Apex\Autentica\Core\Listeners;

use Apex\Autentica\Core\Services\SuspensionService;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

/**
 * A suspended account is refused at sign-in, and told why — 0.3.0.
 *
 * On the framework's own `Login` event rather than inside one login form, so EVERY way in is
 * covered: the password form, a social login, a host's own controller. The guard has already
 * logged the user in when this fires, so it logs them straight out again and throws a
 * validation error — which a form-based login shows against the email field, like any other
 * refusal.
 */
class RefuseSuspendedLogin
{
    public function __construct(private SuspensionService $suspensions)
    {
    }

    public function handle(Login $event): void
    {
        if (! $this->suspensions->isSuspended($event->user)) {
            return;
        }

        Auth::guard($event->guard)->logout();

        throw ValidationException::withMessages([
            'email' => __('autentica::auth.suspended'),
        ]);
    }
}

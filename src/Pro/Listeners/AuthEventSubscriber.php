<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Records sign-ins, sign-outs, failures and lockouts by listening to the
 *              framework's own authentication events.
 * File Location: exorgroup/apex-autentica/src/Pro/Listeners/AuthEventSubscriber.php
 */

namespace Apex\Autentica\Pro\Listeners;

use Apex\Autentica\Pro\Services\SessionManager;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\Log;

/**
 * Turns the framework's auth events into Autentica's audit trail.
 *
 * The alternative is asking every application to call logSuccessfulLogin() from its own login
 * controller, which means an audit trail that is only as complete as the places somebody
 * remembered to instrument. Laravel already fires these events from every path that
 * authenticates — form login, remember cookie, API guard, programmatic Auth::login() — so
 * listening here records all of them and stays right when a new path is added.
 *
 * Every handler swallows its own errors. Logging must never be the reason somebody cannot
 * sign in; a missing audit row is a smaller problem than a locked-out organisation.
 */
class AuthEventSubscriber
{
    public function __construct(private readonly SessionManager $sessions)
    {
    }

    /**
     * Someone signed in.
     *
     * @param Login $event
     * @return void
     */
    public function handleLogin(Login $event): void
    {
        $user = $event->user;

        if ($this->loggingEvents() && method_exists($user, 'logSuccessfulLogin')) {
            try {
                $user->logSuccessfulLogin([
                    'guard' => $event->guard,
                    'remember' => $event->remember,
                ]);
            } catch (\Exception $e) {
                Log::error('AuthEventSubscriber.php - handleLogin() logging error: ' . $e->getMessage());
            }
        }

        // The session row is deliberately NOT created here. Laravel fires this event from
        // Auth::attempt(), and the login controller calls session()->regenerate() immediately
        // afterwards — so the id available at this moment is about to be thrown away. A row
        // recorded now points at a session that never exists: revoking it deletes nothing and
        // the device stays signed in.
        //
        // TrackSessionActivity creates it instead, on the way out of the request, once the id
        // is final. That also covers logins the framework performs without a controller.
    }

    /**
     * Someone signed out.
     *
     * @param Logout $event
     * @return void
     */
    public function handleLogout(Logout $event): void
    {
        // Nullable on the framework's event: a logout can fire with no resolved user.
        $user = $event->user;

        if (! $user) {
            return;
        }

        if ($this->loggingEvents() && method_exists($user, 'logLogout')) {
            try {
                $user->logLogout(['guard' => $event->guard]);
            } catch (\Exception $e) {
                Log::error('AuthEventSubscriber.php - handleLogout() logging error: ' . $e->getMessage());
            }
        }

        if ($this->trackingSessions()) {
            try {
                // Only this device's row. Signing out of one browser must not clear the
                // list of the user's other sessions.
                $this->sessions->forgetSession(session()->getId());
            } catch (\Exception $e) {
                Log::error('AuthEventSubscriber.php - handleLogout() session error: ' . $e->getMessage());
            }
        }
    }

    /**
     * Someone tried to sign in and could not.
     *
     * @param Failed $event
     * @return void
     */
    public function handleFailed(Failed $event): void
    {
        if (! $this->loggingEvents() || ! config('autentica_pro.events.log_failed_logins', true)) {
            return;
        }

        try {
            $userModel = \Apex\Autentica\Core\Support\Autentica::userModel();

            if (! method_exists($userModel, 'logFailedLogin')) {
                return;
            }

            // The address typed in, not a user id: a failure most often means no such
            // account, and those attempts are exactly the ones worth keeping.
            $email = $event->credentials['email']
                ?? $event->credentials['username']
                ?? ($event->user?->email);

            if (! $email) {
                return;
            }

            $userModel::logFailedLogin($email, ['guard' => $event->guard]);

            // logFailedLogin() raises a security event only when the address belongs to
            // somebody, so failures against addresses with no account would exist as a login
            // attempt and nothing else. Those are the ones worth seeing: a run of them is
            // somebody guessing at who has an account here. Recorded with a null user, which
            // is what the column already allows.
            if (! $userModel::where('email', $email)->exists()) {
                \Apex\Autentica\Core\Models\SecurityEvent::create([
                    'user_id' => null,
                    'event_type' => \Apex\Autentica\Core\Models\SecurityEvent::TYPE_LOGIN_FAILED,
                    'event_data' => ['email' => $email, 'guard' => $event->guard, 'account_exists' => false],
                    'ip_address' => request()->ip(),
                    'user_agent' => request()->userAgent(),
                ]);
            }
        } catch (\Exception $e) {
            Log::error('AuthEventSubscriber.php - handleFailed() method error: ' . $e->getMessage());
        }
    }

    /**
     * Too many failures from one place; the throttle closed the door.
     *
     * @param Lockout $event
     * @return void
     */
    public function handleLockout(Lockout $event): void
    {
        if (! $this->loggingEvents()) {
            return;
        }

        try {
            $email = $event->request->input('email') ?? $event->request->input('username');

            if (! $email) {
                return;
            }

            $userModel = \Apex\Autentica\Core\Support\Autentica::userModel();
            $user = $userModel::where('email', $email)->first();

            if ($user && method_exists($user, 'logSecurityEvent')) {
                $user->logSecurityEvent(\Apex\Autentica\Core\Models\SecurityEvent::TYPE_ACCOUNT_LOCKED, [
                    'reason' => 'too_many_attempts',
                    'ip_address' => $event->request->ip(),
                ]);
            }
        } catch (\Exception $e) {
            Log::error('AuthEventSubscriber.php - handleLockout() method error: ' . $e->getMessage());
        }
    }

    /**
     * A password was actually changed through a reset link.
     *
     * @param PasswordReset $event
     * @return void
     */
    public function handlePasswordReset(PasswordReset $event): void
    {
        if (! $this->loggingEvents() || ! method_exists($event->user, 'logPasswordChange')) {
            return;
        }

        try {
            $event->user->logPasswordChange(['method' => 'reset_link']);
        } catch (\Exception $e) {
            Log::error('AuthEventSubscriber.php - handlePasswordReset() method error: ' . $e->getMessage());
        }
    }

    /**
     * Map events to handlers.
     *
     * @param Dispatcher $events
     * @return array<string, string>
     */
    public function subscribe(Dispatcher $events): array
    {
        return [
            Login::class => 'handleLogin',
            Logout::class => 'handleLogout',
            Failed::class => 'handleFailed',
            Lockout::class => 'handleLockout',
            PasswordReset::class => 'handlePasswordReset',
        ];
    }

    /**
     * Is security event logging switched on?
     *
     * @return bool
     */
    private function loggingEvents(): bool
    {
        return (bool) config('autentica_pro.events.log', true);
    }

    /**
     * Is session tracking switched on?
     *
     * @return bool
     */
    private function trackingSessions(): bool
    {
        return (bool) config('autentica_pro.sessions.track', true);
    }
}

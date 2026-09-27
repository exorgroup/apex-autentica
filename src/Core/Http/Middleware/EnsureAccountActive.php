<?php

namespace Apex\Autentica\Core\Http\Middleware;

use Apex\Autentica\Core\Services\SuspensionService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;

/**
 * A suspended account's session ends the next time it is used — 0.3.0.
 *
 * `SuspensionService::suspend()` deletes the sessions it can find, which with the `database`
 * driver is all of them. This is for the ones it cannot: another driver, a remember-me cookie,
 * a tab that was open when the suspension happened. One indexed `exists` per signed-in request.
 */
class EnsureAccountActive
{
    public function __construct(private SuspensionService $suspensions)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user || ! $this->suspensions->isSuspended($user)) {
            return $next($request);
        }

        Auth::guard()->logout();

        if ($request->hasSession()) {
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        $message = __('autentica::auth.suspended');

        if ($request->expectsJson()) {
            return response()->json(['message' => $message], 403);
        }

        $route = config('autentica.auth.suspension.redirect_route', 'login');

        return redirect(Route::has($route) ? route($route) : '/')->withErrors(['email' => $message]);
    }
}

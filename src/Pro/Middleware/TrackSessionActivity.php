<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Keeps au10_sessions.last_activity current without writing on every request.
 * File Location: exorgroup/apex-autentica/src/Pro/Middleware/TrackSessionActivity.php
 */

namespace Apex\Autentica\Pro\Middleware;

use Apex\Autentica\Pro\Services\SessionManager;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * Records the signed-in session, and marks it as still in use.
 *
 * Both jobs live here rather than on the Login event, because that event fires from
 * Auth::attempt() and the login controller regenerates the session id straight afterwards. A
 * row written at event time carries an id that is discarded a moment later, which makes the
 * revoke button delete a session that does not exist and leaves the device signed in. This
 * middleware runs on the way out of the request, by which point the id is settled.
 *
 * Without the activity half, "last active" would read as the moment somebody signed in and
 * never move, so a session abandoned days ago would look identical to the one in use right now
 * — exactly the distinction the sessions list exists to draw.
 *
 * Both are throttled through the session itself rather than the database: an untimed version
 * would add a write to every request, including every poll of a seat map.
 */
class TrackSessionActivity
{
    private const STAMP_KEY = 'autentica.activity_stamped_at';
    private const TRACKED_KEY = 'autentica.tracked_session_id';

    public function __construct(private readonly SessionManager $sessions)
    {
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        try {
            if (! config('autentica_pro.sessions.track', true) || ! $request->user()) {
                return $response;
            }

            $sessionId = $request->session()->getId();

            // The id we last wrote a row for is kept in the session, so the common case costs
            // no query at all. It differs from the current id in exactly two situations: a
            // session that has just been created, and one whose id was regenerated — which is
            // what happens immediately after signing in. Both want a row against the new id.
            if ($request->session()->get(self::TRACKED_KEY) !== $sessionId) {
                $this->sessions->createSession($request->user(), $request);

                $request->session()->put(self::TRACKED_KEY, $sessionId);
                $request->session()->put(self::STAMP_KEY, time());

                return $response;
            }

            $throttle = (int) config('autentica_pro.sessions.activity_throttle_seconds', 60);
            $last = $request->session()->get(self::STAMP_KEY);

            if ($last && (time() - (int) $last) < $throttle) {
                return $response;
            }

            $request->session()->put(self::STAMP_KEY, time());
            $this->sessions->updateActivity($sessionId, $request->ip());
        } catch (\Exception $e) {
            // Bookkeeping. Never worth failing a request the user asked for.
            Log::error('TrackSessionActivity.php - handle() method error: ' . $e->getMessage());
        }

        return $response;
    }
}

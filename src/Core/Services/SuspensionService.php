<?php

namespace Apex\Autentica\Core\Services;

use Apex\Autentica\Core\Exceptions\SuspensionException;
use Apex\Autentica\Core\Models\AccountSuspension;
use Apex\Autentica\Core\Models\Group;
use Apex\Autentica\Core\Models\SecurityEvent;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Schema;

/**
 * Stopping an account from signing in, without deleting it — 0.3.0.
 *
 * The account, its orders and its history stay; it simply cannot sign in, and every session it
 * already has is ended. Lifting it lets it sign in again. Both are recorded in the security log
 * with who did it.
 *
 * Enforced in TWO places, because either alone has a gap:
 *  - at sign-in (`RefuseSuspendedLogin`), so a suspended account is told why and let no further
 *  - on every request (`EnsureAccountActive`), so a session that survived — a driver whose sessions
 *    cannot be listed, a remember-me cookie — is ended the next time it is used
 *
 * The logic lives here, not in a UI, for the reason `GroupAdministration` gives: a UI is not the
 * only way in, and a host that writes its own screen must inherit every guard.
 */
class SuspensionService
{
    public function __construct(private GroupAdministration $groups)
    {
    }

    public function isSuspended(Model $user): bool
    {
        return AccountSuspension::active()->where('user_id', $user->getKey())->exists();
    }

    /**
     * Which of these ids are suspended — one query for a whole page of users.
     *
     * @param array<int, int> $userIds
     * @return array<int, int>
     */
    public function suspendedAmong(array $userIds): array
    {
        if ($userIds === []) {
            return [];
        }

        return AccountSuspension::active()
            ->whereIn('user_id', $userIds)
            ->distinct()
            ->pluck('user_id')
            ->map(fn ($id) => (int) $id)
            ->all();
    }

    /**
     * The active suspension, if any — for "suspended since … by …".
     */
    public function current(Model $user): ?AccountSuspension
    {
        return AccountSuspension::active()->where('user_id', $user->getKey())->latest('suspended_at')->first();
    }

    /**
     * Suspend an account.
     *
     * Idempotent: suspending a suspended account changes nothing and logs nothing, so a retried
     * request cannot stack suspensions.
     *
     * @throws SuspensionException
     */
    public function suspend(Model $user, ?Model $by = null, ?string $reason = null): void
    {
        if ($by && $by->getKey() === $user->getKey()) {
            throw new SuspensionException("You can't suspend your own account.");
        }

        if ($this->isSuspended($user)) {
            return;
        }

        if ($group = $this->lastActiveProtectedMemberOf($user)) {
            throw new SuspensionException(
                "This is the last active member of {$group->name}. Add another before suspending this one."
            );
        }

        DB::transaction(function () use ($user, $by, $reason) {
            AccountSuspension::create([
                'user_id' => $user->getKey(),
                'suspended_by' => $by?->getKey(),
                'reason' => $reason,
                'suspended_at' => now(),
            ]);

            $this->endSessions($user);
        });

        $this->record($user, 'account_suspended', $by, $reason);
    }

    /**
     * Lift a suspension. Idempotent, like `suspend()`.
     */
    public function reinstate(Model $user, ?Model $by = null): void
    {
        $lifted = AccountSuspension::active()
            ->where('user_id', $user->getKey())
            ->update(['lifted_at' => now(), 'lifted_by' => $by?->getKey()]);

        if ($lifted > 0) {
            $this->record($user, 'account_reinstated', $by);
        }
    }

    /**
     * The protected group this user is the last ACTIVE member of, if any.
     *
     * Active, not merely a member: two administrators of whom one is already suspended is one
     * administrator, and suspending the other locks everybody out.
     */
    private function lastActiveProtectedMemberOf(Model $user): ?Group
    {
        foreach ($this->groups->protectedGroups() as $name) {
            $group = Group::where('name', $name)->first();

            if (! $group || ! $group->users()->whereKey($user->getKey())->exists()) {
                continue;
            }

            $memberIds = $group->users()->pluck($group->users()->getRelated()->getQualifiedKeyName())->all();
            $active = array_diff($memberIds, $this->suspendedAmong($memberIds));

            if (count($active) <= 1) {
                return $group;
            }
        }

        return null;
    }

    /**
     * "Signs them out everywhere".
     *
     * Laravel's own session rows, when the driver is `database` and so they can be found — the
     * other drivers are covered by `EnsureAccountActive` on the next request. And Pro's session
     * tracking rows, soft-deleted as everything is.
     */
    private function endSessions(Model $user): void
    {
        if (config('session.driver') === 'database') {
            $table = config('session.table', 'sessions');

            if (Schema::hasTable($table)) {
                DB::table($table)->where('user_id', $user->getKey())->delete();
            }
        }

        if (Schema::hasTable('au10_sessions') && Schema::hasColumn('au10_sessions', 'deleted_at')) {
            DB::table('au10_sessions')
                ->where('user_id', $user->getKey())
                ->whereNull('deleted_at')
                ->update(['deleted_at' => now()]);
        }
    }

    /**
     * Written whatever else happens — "who stopped my account, and when" has a real answer.
     * `medium`: the column is an enum and anything else is a QueryException (TBX AF2-415).
     */
    private function record(Model $user, string $type, ?Model $by, ?string $reason = null): void
    {
        SecurityEvent::create([
            'user_id' => $user->getKey(),
            'event_type' => $type,
            'event_data' => array_filter([
                'by_user_id' => $by?->getKey(),
                'by_email' => $by?->email ?? null,
                'reason' => $reason,
            ], fn ($v) => $v !== null),
            'severity' => 'medium',
            'occurred_at' => now(),
            'ip_address' => Request::ip(),
            'user_agent' => Request::userAgent(),
        ]);
    }
}

<?php

namespace Apex\Autentica\Tests;

use Apex\Autentica\Core\Exceptions\SuspensionException;
use Apex\Autentica\Core\Models\AccountSuspension;
use Apex\Autentica\Core\Models\Group;
use Apex\Autentica\Core\Models\SecurityEvent;
use Apex\Autentica\Core\Services\SuspensionService;
use Apex\Autentica\Tests\Fixtures\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;

/**
 * Account suspension — 0.3.0.
 *
 * The service's guards (self, last active protected member), idempotence, the history row, the
 * security events, the session wipe, and the two places it is enforced: at sign-in and on the
 * next request.
 */
class SuspensionTest extends TestCase
{
    private SuspensionService $service;

    public function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('session.driver', 'database');
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
    }

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $t) {
            $t->id();
            $t->string('name');
            $t->string('email');
            $t->string('password')->nullable();
            $t->rememberToken();
            $t->timestamps();
        });

        Schema::create('sessions', function (Blueprint $t) {
            $t->string('id')->primary();
            $t->foreignId('user_id')->nullable()->index();
            $t->string('ip_address', 45)->nullable();
            $t->text('user_agent')->nullable();
            $t->longText('payload');
            $t->integer('last_activity')->index();
        });

        $this->loadMigrationsFrom(__DIR__.'/../database/tenant/migrations/core');
        $this->artisan('migrate')->run();

        $this->service = $this->app->make(SuspensionService::class);
    }

    private function user(string $name): User
    {
        return User::create(['name' => $name, 'email' => strtolower($name).'@probe.test', 'password' => bcrypt('secret')]);
    }

    private function admins(User ...$users): Group
    {
        $group = Group::firstOrCreate(['name' => 'Administrators'], ['description' => 'test']);

        foreach ($users as $u) {
            DB::table('au10_group_user')->insert([
                'user_id' => $u->id, 'group_id' => $group->id, 'created_at' => now(), 'updated_at' => now(),
            ]);
        }

        return $group;
    }

    /** @test */
    public function it_suspends_and_records_who_did_it(): void
    {
        [$by, $target] = [$this->user('Boss'), $this->user('Target')];

        $this->service->suspend($target, $by, 'Left the company');

        $this->assertTrue($this->service->isSuspended($target));
        $this->assertSame([$target->id], $this->service->suspendedAmong([$by->id, $target->id]));

        $row = AccountSuspension::first();
        $this->assertSame($by->id, (int) $row->suspended_by);
        $this->assertSame('Left the company', $row->reason);

        $event = SecurityEvent::where('event_type', SecurityEvent::TYPE_ACCOUNT_SUSPENDED)->first();
        $this->assertNotNull($event);
        $this->assertSame($target->id, (int) $event->user_id);
    }

    /** @test */
    public function suspending_twice_changes_nothing(): void
    {
        $target = $this->user('Target');

        $this->service->suspend($target, $this->user('Boss'));
        $this->service->suspend($target, $this->user('Other'));

        $this->assertSame(1, AccountSuspension::count());
        $this->assertSame(1, SecurityEvent::where('event_type', 'account_suspended')->count());
    }

    /** @test */
    public function nobody_can_suspend_themselves(): void
    {
        $me = $this->user('Me');

        $this->expectException(SuspensionException::class);
        $this->service->suspend($me, $me);
    }

    /** @test */
    public function the_last_active_administrator_cannot_be_suspended(): void
    {
        $only = $this->user('Only');
        $this->admins($only);

        $this->expectException(SuspensionException::class);
        $this->service->suspend($only, $this->user('Someone'));
    }

    /** @test */
    public function an_administrator_with_an_active_colleague_can_be(): void
    {
        [$a, $b] = [$this->user('Alpha'), $this->user('Beta')];
        $this->admins($a, $b);

        $this->service->suspend($a, $b);

        $this->assertTrue($this->service->isSuspended($a));
    }

    /** @test */
    public function a_suspended_colleague_does_not_count_as_active(): void
    {
        /* Two administrators of whom one is suspended is ONE administrator. */
        [$a, $b, $c] = [$this->user('Alpha'), $this->user('Beta'), $this->user('Gamma')];
        $this->admins($a, $b);
        $this->service->suspend($a, $b);

        $this->expectException(SuspensionException::class);
        $this->service->suspend($b, $c);
    }

    /** @test */
    public function reinstating_lifts_it_and_is_recorded(): void
    {
        [$by, $target] = [$this->user('Boss'), $this->user('Target')];
        $this->service->suspend($target, $by);

        $this->service->reinstate($target, $by);
        $this->service->reinstate($target, $by);

        $this->assertFalse($this->service->isSuspended($target));
        $this->assertNotNull(AccountSuspension::first()->lifted_at);
        $this->assertSame(1, SecurityEvent::where('event_type', 'account_reinstated')->count(), 'a second reinstate logged again');
    }

    /** @test */
    public function suspending_ends_the_database_sessions(): void
    {
        [$target, $other] = [$this->user('Target'), $this->user('Other')];

        DB::table('sessions')->insert([
            ['id' => 's1', 'user_id' => $target->id, 'payload' => '', 'last_activity' => time()],
            ['id' => 's2', 'user_id' => $target->id, 'payload' => '', 'last_activity' => time()],
            ['id' => 's3', 'user_id' => $other->id, 'payload' => '', 'last_activity' => time()],
        ]);

        $this->service->suspend($target, $other);

        $this->assertSame(0, DB::table('sessions')->where('user_id', $target->id)->count());
        $this->assertSame(1, DB::table('sessions')->where('user_id', $other->id)->count(), 'somebody else was signed out');
    }

    /** @test */
    public function a_suspended_account_is_refused_at_sign_in(): void
    {
        $target = $this->user('Target');
        $this->service->suspend($target, $this->user('Boss'));

        try {
            Auth::attempt(['email' => 'target@probe.test', 'password' => 'secret']);
            $this->fail('a suspended account signed in');
        } catch (ValidationException $e) {
            $this->assertArrayHasKey('email', $e->errors());
        }

        $this->assertFalse(Auth::check(), 'the refusal left the account signed in');
    }

    /** @test */
    public function an_active_account_still_signs_in(): void
    {
        $this->user('Target');

        $this->assertTrue(Auth::attempt(['email' => 'target@probe.test', 'password' => 'secret']));
    }

    /** @test */
    public function a_surviving_session_ends_on_its_next_request(): void
    {
        Route::middleware('web')->get('/probe', fn () => 'inside');

        $target = $this->user('Target');
        $this->actingAs($target)->get('/probe')->assertOk()->assertSee('inside');

        $this->service->suspend($target, $this->user('Boss'));

        $this->actingAs($target)->get('/probe')->assertRedirect();
        $this->assertFalse(Auth::check());
        $this->actingAs($target)->getJson('/probe')->assertForbidden();
    }
}

<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Checks that Autentica's models, schema, configuration and signatures agree.
 * URL: exorgroup/apex-autentica/src/Core/Console/DoctorCommand.php
 */

namespace Apex\Autentica\Core\Console;

use Apex\Autentica\Core\Support\Autentica;
use Apex\Signature\SignatureService;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * A model and its table drifting apart is the failure mode that has bitten this package
 * hardest: a column declared but never created, a pivot attribute written to a table that
 * has no such column. Those do not announce themselves — they throw inside a try/catch, or
 * they silently write nothing — so this command goes looking for them deliberately.
 *
 * Exits non-zero when anything is wrong, so it can gate a deployment.
 */
class DoctorCommand extends Command
{
    protected $signature = 'autentica:doctor {--details : Also list every check that passed}';

    protected $description = 'Check that Autentica models, schema, config and signatures agree';

    /** @var array<int, array{level: string, area: string, message: string, fix: string|null}> */
    private array $findings = [];

    private int $checks = 0;

    public function handle(): int
    {
        $this->line('');
        $this->line('  <options=bold>Autentica Doctor</>');
        $this->line('');

        $this->checkTables();
        $this->checkColumns();
        $this->checkPivots();
        $this->checkConfig();
        $this->checkSessionTracking();
        $this->checkOrphans();
        $this->checkSignatures();

        return $this->report();
    }

    /**
     * Every model's table must exist.
     */
    private function checkTables(): void
    {
        foreach ($this->models() as $class => $model) {
            $table = $model->getTable();
            $this->checks++;

            if (! Schema::hasTable($table)) {
                $this->recordError('schema', "{$this->short($class)}: table '{$table}' does not exist", 'Publish and run the Autentica migrations.');
                continue;
            }

            $this->recordPass('schema', "{$this->short($class)} -> {$table}");
        }
    }

    /**
     * Fillable columns, casts and soft-delete columns must all exist.
     */
    private function checkColumns(): void
    {
        foreach ($this->models() as $class => $model) {
            $table = $model->getTable();

            if (! Schema::hasTable($table)) {
                continue;
            }

            $columns = Schema::getColumnListing($table);

            foreach ($model->getFillable() as $field) {
                $this->checks++;

                if (! in_array($field, $columns, true)) {
                    $this->recordError('columns', "{$table}.{$field} is fillable but the column does not exist", 'Remove it from $fillable, or add the column.');
                } else {
                    $this->recordPass('columns', "{$table}.{$field}");
                }
            }

            foreach (array_keys($model->getCasts()) as $field) {
                $this->checks++;

                // The primary key is cast by default but is not always a real column name.
                if ($field === $model->getKeyName() || in_array($field, $columns, true)) {
                    $this->recordPass('casts', "{$table}.{$field}");
                } else {
                    $this->recordError('casts', "{$table}.{$field} is cast but the column does not exist", 'Remove the cast, or add the column.');
                }
            }

            $this->checks++;

            if (in_array(SoftDeletes::class, class_uses_recursive($class), true)) {
                if (in_array('deleted_at', $columns, true)) {
                    $this->recordPass('soft deletes', "{$table}.deleted_at");
                } else {
                    $this->recordError('soft deletes', "{$this->short($class)} uses SoftDeletes but {$table} has no deleted_at", 'Add $table->softDeletes() to the migration. Every query on this model fails without it.');
                }
            }
        }
    }

    /**
     * Pivot columns declared on a relation must exist on the pivot table.
     *
     * This is the check that catches writing to a column the table does not have — the bug
     * that silently emptied users' group membership.
     */
    private function checkPivots(): void
    {
        $userModel = Autentica::userModel();

        if (! class_exists($userModel)) {
            $this->recordError('pivot', "configured user model {$userModel} does not exist", 'Check config auth.providers.users.model.');

            return;
        }

        $user = new $userModel();

        if (! method_exists($user, 'groups')) {
            $this->recordWarning('pivot', "{$this->short($userModel)} does not use HasGroups", 'Add the HasGroups trait to your user model.');

            return;
        }

        $relation = $user->groups();
        $table = $relation->getTable();

        $this->checks++;

        if (! Schema::hasTable($table)) {
            $this->recordError('pivot', "pivot table '{$table}' does not exist", 'Run the Autentica migrations.');

            return;
        }

        $columns = Schema::getColumnListing($table);

        foreach ($relation->getPivotColumns() as $field) {
            $this->checks++;

            // withTimestamps() adds these; they are real columns and are checked like any other.
            if (in_array($field, $columns, true)) {
                $this->recordPass('pivot', "{$table}.{$field}");
            } else {
                $this->recordError('pivot', "{$table}.{$field} is declared in withPivot() but the column does not exist", 'Attaching would throw and, inside sync(), would leave the user in no group at all.');
            }
        }
    }

    /**
     * Every config key the package reads must resolve.
     */
    private function checkConfig(): void
    {
        $keys = [
            'autentica.permissions.cache.enabled',
            'autentica.permissions.cache.ttl',
            'autentica.permissions.custom.separator',
            'autentica.auth.password_policies.min_length',
            'autentica.auth.security.max_login_attempts',
            'autentica.tenancy.enabled',
            'apex.signature.enabled',
        ];

        foreach ($keys as $key) {
            $this->checks++;

            if (config($key) === null) {
                $this->recordError('config', "{$key} does not resolve", 'Publish the package config: php artisan vendor:publish --tag=autentica-config');
            } else {
                $this->recordPass('config', $key);
            }
        }
    }

    /**
     * Can the audit trail actually be written, and can a revoked session actually be ended?
     *
     * These fail quietly by design — logging must never break a sign-in — so nothing tells you
     * they are broken except an audit table that stays empty and a revoke button that does not
     * revoke. This is where that gets noticed.
     */
    private function checkSessionTracking(): void
    {
        if (! class_exists(\Apex\Autentica\Pro\Listeners\AuthEventSubscriber::class)) {
            $this->checks++;
            $this->recordInfo('sessions', 'Pro is not installed — no automatic event logging');

            return;
        }

        // A published config predating this feature keeps its own 'sessions' array, and
        // mergeConfigFrom is shallow, so nested keys the package added never appear. The code
        // falls back to its defaults, but the published file is then quietly out of date.
        foreach ([
            'autentica_pro.sessions.track',
            'autentica_pro.events.log',
        ] as $key) {
            $this->checks++;

            if (config($key) === null) {
                $this->recordWarning(
                    'sessions',
                    "{$key} is missing from the published config",
                    'Your config/autentica_pro.php predates this setting. Re-publish it, or copy the new keys across. The package default applies meanwhile.'
                );
            } else {
                $this->recordPass('sessions', $key);
            }
        }

        // Whether a revoke can end the session depends entirely on where sessions are kept.
        $this->checks++;
        $driver = config('session.driver');

        if (in_array($driver, ['database', 'file'], true)) {
            $this->recordPass('sessions', "revoke can terminate sessions on the '{$driver}' driver");
        } else {
            $this->recordWarning(
                'sessions',
                "session driver '{$driver}' cannot be reached to terminate a session",
                'Revoking removes the device from the list but leaves it signed in. Use the database or file driver if revoke has to mean revoke.'
            );
        }

        // The database driver needs its own table, separate from au10_sessions.
        if ($driver === 'database') {
            $this->checks++;
            $table = config('session.table', 'sessions');

            if (Schema::hasTable($table)) {
                $this->recordPass('sessions', "framework session table '{$table}' exists");
            } else {
                $this->recordError(
                    'sessions',
                    "session.driver is 'database' but table '{$table}' does not exist",
                    'Run php artisan session:table && php artisan migrate.'
                );
            }
        }

        // Tracking with no listener registered means the sessions list stays empty forever.
        $this->checks++;
        $registered = ! empty(\Illuminate\Support\Facades\Event::getListeners(\Illuminate\Auth\Events\Login::class));

        if ($registered) {
            $this->recordPass('sessions', 'authentication events are being listened to');
        } else {
            $this->recordError(
                'sessions',
                'nothing is listening to the framework Login event',
                'Autentica Pro registers AuthEventSubscriber in its provider. Check the licence gate and that the Pro provider is loading.'
            );
        }
    }

    /**
     * Rows pointing at things that no longer exist.
     */
    private function checkOrphans(): void
    {
        if (Schema::hasTable('au10_permissions') && Schema::hasTable('au10_system_resources')) {
            $this->checks++;
            $count = DB::table('au10_permissions')
                ->leftJoin('au10_system_resources', 'au10_permissions.system_resource_id', '=', 'au10_system_resources.id')
                ->whereNull('au10_system_resources.id')
                ->count();

            $count > 0
                ? $this->recordWarning('orphans', "{$count} permission row(s) reference a system resource that no longer exists", 'Re-run your resource sync, or delete them.')
                : $this->recordPass('orphans', 'permissions all point at live resources');
        }

        if (Schema::hasTable('au10_group_user') && Schema::hasTable('au10_groups')) {
            $this->checks++;
            $count = DB::table('au10_group_user')
                ->leftJoin('au10_groups', 'au10_group_user.group_id', '=', 'au10_groups.id')
                ->whereNull('au10_groups.id')
                ->count();

            $count > 0
                ? $this->recordWarning('orphans', "{$count} membership row(s) reference a group that no longer exists", 'Delete them, or restore the group.')
                : $this->recordPass('orphans', 'memberships all point at live groups');
        }
    }

    /**
     * Signature coverage, and whether what is signed still verifies.
     */
    private function checkSignatures(): void
    {
        $signatures = app(SignatureService::class);

        if (! $signatures->enabled('autentica')) {
            $this->recordInfo('signatures', 'signing is off (APEX_SIGNATURE_ENABLED) — nothing to verify');

            return;
        }

        if (! Schema::hasTable('au10_group_user')) {
            return;
        }

        $rows = DB::table('au10_group_user')->get();
        $unsigned = 0;
        $failed = 0;

        foreach ($rows as $row) {
            if (! isset($row->signature) || (string) $row->signature === '') {
                $unsigned++;
                continue;
            }

            $valid = $signatures->verify([
                'user_id' => $row->user_id,
                'group_id' => $row->group_id,
                'assigned_at' => $row->assigned_at,
                'assigned_by' => $row->assigned_by,
            ], $row->signature, 'autentica');

            if (! $valid) {
                $failed++;
            }
        }

        $this->checks++;
        $signed = $rows->count() - $unsigned;

        $this->recordInfo('signatures', "au10_group_user: {$signed} signed, {$unsigned} unsigned, {$failed} failing");

        // Unsigned is not an alarm: those rows were written while signing was off.
        if ($unsigned > 0) {
            $this->recordInfo('signatures', "{$unsigned} row(s) predate signing and cannot be verified");
        }

        if ($failed > 0) {
            $this->recordError('signatures', "{$failed} membership row(s) FAIL verification", 'The row was altered after signing, or the signing key changed. Set APEX_SIGNATURE_KEY_PREVIOUS if you have rotated it.');
        }
    }

    /**
     * Every Autentica model, Pro included when it is installed.
     *
     * @return array<class-string, Model>
     */
    private function models(): array
    {
        $classes = [
            \Apex\Autentica\Core\Models\Group::class,
            \Apex\Autentica\Core\Models\Permission::class,
            \Apex\Autentica\Core\Models\SystemResource::class,
            \Apex\Autentica\Core\Models\LoginAttempt::class,
            \Apex\Autentica\Core\Models\SecurityEvent::class,
            \Apex\Autentica\Core\Models\PasswordHistory::class,
            \Apex\Autentica\Core\Models\AuthToken::class,
        ];

        // Named as strings so Core never references Pro at compile time.
        foreach ([
            'Apex\\Autentica\\Pro\\Models\\MfaConfig',
            'Apex\\Autentica\\Pro\\Models\\MfaBackupCode',
            'Apex\\Autentica\\Pro\\Models\\Session',
            'Apex\\Autentica\\Pro\\Models\\SocialAccount',
            'Apex\\Autentica\\Pro\\Models\\TrustedDevice',
            'Apex\\Autentica\\Pro\\Models\\AuthMethod',
        ] as $pro) {
            if (class_exists($pro)) {
                $classes[] = $pro;
            }
        }

        $models = [];

        foreach ($classes as $class) {
            $models[$class] = new $class();
        }

        return $models;
    }

    private function recordPass(string $area, string $message): void
    {
        if ($this->option('details')) {
            $this->line("  <fg=green>ok</>       <fg=gray>{$area}</>  {$message}");
        }
    }

    private function recordInfo(string $area, string $message): void
    {
        $this->line("  <fg=blue>info</>     <fg=gray>{$area}</>  {$message}");
    }

    private function recordWarning(string $area, string $message, ?string $fix = null): void
    {
        $this->findings[] = ['level' => 'warning', 'area' => $area, 'message' => $message, 'fix' => $fix];
    }

    private function recordError(string $area, string $message, ?string $fix = null): void
    {
        $this->findings[] = ['level' => 'error', 'area' => $area, 'message' => $message, 'fix' => $fix];
    }

    /**
     * Print findings, worst first, and decide the exit code.
     */
    private function report(): int
    {
        $errors = array_filter($this->findings, fn ($f) => $f['level'] === 'error');
        $warnings = array_filter($this->findings, fn ($f) => $f['level'] === 'warning');

        foreach (['error' => $errors, 'warning' => $warnings] as $level => $set) {
            foreach ($set as $f) {
                $colour = $level === 'error' ? 'red' : 'yellow';
                $label = str_pad(strtoupper($level), 8);
                $this->line('');
                $this->line("  <fg={$colour};options=bold>{$label}</> <fg=gray>{$f['area']}</>  {$f['message']}");

                if ($f['fix']) {
                    $this->line("           <fg=gray>{$f['fix']}</>");
                }
            }
        }

        $this->line('');

        if (! $this->findings) {
            $this->line("  <fg=green;options=bold>All {$this->checks} checks passed.</>");
            $this->line('');

            return self::SUCCESS;
        }

        $this->line(sprintf(
            '  %d checks, <fg=red>%d error(s)</>, <fg=yellow>%d warning(s)</>.',
            $this->checks,
            count($errors),
            count($warnings)
        ));
        $this->line('');

        return $errors ? self::FAILURE : self::SUCCESS;
    }

    private function short(string $class): string
    {
        return class_basename($class);
    }
}

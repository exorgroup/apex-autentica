<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Account suspension — 0.3.0.
 *
 * A table of Autentica's own rather than a column on the host's `users`: the package never
 * alters a table it does not own, and a row per suspension keeps the HISTORY — who stopped the
 * account, why, when, and who let it back in. An account is suspended while it has a row with
 * `lifted_at` null.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('au10_account_suspensions', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();
            $table->unsignedBigInteger('suspended_by')->nullable();
            $table->string('reason', 500)->nullable();
            $table->timestamp('suspended_at');
            $table->timestamp('lifted_at')->nullable();
            $table->unsignedBigInteger('lifted_by')->nullable();
            $table->string('signature', 128)->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->index(['user_id', 'lifted_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('au10_account_suspensions');
    }
};

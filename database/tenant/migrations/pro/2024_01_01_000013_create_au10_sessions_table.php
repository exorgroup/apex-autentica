<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // This is Autentica's session *tracking* table — it records who is signed in from
        // where, so sessions can be listed and revoked. It is NOT Laravel's session driver
        // table: the framework keeps owning `sessions`. Hence an ordinary auto-increment key
        // with the framework's session id stored alongside it in `session_id`.
        Schema::create('au10_sessions', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('session_id')->unique(); // Laravel's session id
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamp('last_activity')->nullable();
            $table->string('device_id', 64)->nullable();
            $table->boolean('is_mobile')->default(false);
            $table->string('location')->nullable(); // City/Country
            $table->string('signature', 128)->nullable();
            $table->softDeletes();
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->index(['user_id', 'last_activity']);
            $table->index('last_activity');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('au10_sessions');
    }
};
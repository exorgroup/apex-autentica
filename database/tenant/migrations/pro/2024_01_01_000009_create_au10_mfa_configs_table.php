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
        Schema::create('au10_mfa_configs', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->unique();
            $table->boolean('enabled')->default(false);
            // Encrypted at rest by TOTPService — the ciphertext is far longer than the
            // secret, so these must be text, not string(255).
            $table->text('secret')->nullable(); // TOTP secret
            $table->text('recovery_codes')->nullable(); // JSON array of recovery codes
            $table->enum('method', ['totp', 'sms', 'email'])->default('totp');
            $table->string('phone', 32)->nullable(); // Destination for the 'sms' method
            $table->timestamp('verified_at')->nullable(); // First successful code entry
            $table->timestamp('enabled_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->string('signature', 128)->nullable();
            $table->softDeletes();
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->index(['user_id', 'enabled']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('au10_mfa_configs');
    }
};
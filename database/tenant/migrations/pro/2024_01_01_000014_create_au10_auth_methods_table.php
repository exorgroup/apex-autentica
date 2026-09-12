<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * APEX Pro Laravel Autentica Authentication System
 * Description: Creates au10_auth_methods — the per-user record of which authentication
 *              methods are available and enabled (password, totp, sms, email, social).
 * File Location: exorgroup/apex-autentica/database/tenant/migrations/2024_01_01_000014_create_au10_auth_methods_table.php
 */

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
        Schema::create('au10_auth_methods', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('method', 32); // password | totp | sms | email | social
            $table->boolean('enabled')->default(false);
            $table->json('config')->nullable(); // Method-specific settings
            $table->timestamp('last_used_at')->nullable();
            $table->string('signature', 128)->nullable();
            $table->softDeletes();
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');

            // A user holds at most one row per method.
            $table->unique(['user_id', 'method']);
            $table->index(['user_id', 'enabled']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('au10_auth_methods');
    }
};

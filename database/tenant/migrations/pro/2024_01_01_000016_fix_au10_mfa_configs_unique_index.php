<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Widens the au10_mfa_configs uniqueness from the user to the user and method.
 * File Location: exorgroup/apex-autentica/database/tenant/migrations/pro/2024_01_01_000016_fix_au10_mfa_configs_unique_index.php
 */

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The table's `method` column has always allowed totp, sms and email, but the unique index was
 * on user_id alone, so an account could only ever hold one of them. Anyone enrolling a second
 * method hit a constraint violation rather than a second row.
 */
return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        Schema::table('au10_mfa_configs', function (Blueprint $table) {
            $table->dropUnique('au10_mfa_configs_user_id_unique');
            $table->unique(['user_id', 'method'], 'au10_mfa_configs_user_method_unique');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::table('au10_mfa_configs', function (Blueprint $table) {
            $table->dropUnique('au10_mfa_configs_user_method_unique');
            $table->unique('user_id', 'au10_mfa_configs_user_id_unique');
        });
    }
};

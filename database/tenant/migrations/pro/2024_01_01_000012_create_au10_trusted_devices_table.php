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
        Schema::create('au10_trusted_devices', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('device_id', 64)->unique(); // Unique device identifier
            $table->string('device_name')->nullable(); // User-friendly device name
            $table->string('ip_address', 45);
            $table->text('user_agent');
            $table->string('browser')->nullable(); // Parsed from the user agent
            $table->string('platform')->nullable(); // Parsed from the user agent
            $table->string('device_fingerprint')->nullable(); // Browser fingerprint
            $table->timestamp('trusted_at');
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->boolean('is_active')->default(true);
            $table->string('signature', 128)->nullable();
            $table->softDeletes();
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->index(['user_id', 'is_active']);
            $table->index('expires_at');
            $table->index('last_used_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('au10_trusted_devices');
    }
};
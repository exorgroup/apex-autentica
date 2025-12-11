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
        Schema::create('Au10_social_accounts', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('provider'); // google, facebook, github, etc.
            $table->string('provider_id'); // ID from the social provider
            $table->string('provider_email')->nullable();
            $table->string('avatar')->nullable();
            $table->json('provider_data')->nullable(); // Additional data from provider
            $table->timestamp('last_login_at')->nullable();
            $table->string('signature', 128)->nullable();
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->unique(['provider', 'provider_id']);
            $table->index(['user_id', 'provider']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('Au10_social_accounts');
    }
};
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
        Schema::create('au10_password_histories', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            // Named 'password' to match users.password — it stores the same hash.
            $table->string('password');
            $table->timestamp('created_at');
            $table->string('signature', 128)->nullable();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->index(['user_id', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('au10_password_histories');
    }
};
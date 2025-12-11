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
        Schema::create('Au10_permissions', function (Blueprint $table) {
            $table->id();
            $table->string('permissionable_type'); // User, Group, etc.
            $table->unsignedBigInteger('permissionable_id');
            $table->unsignedBigInteger('system_resource_id');
            $table->boolean('can_create')->default(false);
            $table->boolean('can_read')->default(false);
            $table->boolean('can_update')->default(false);
            $table->boolean('can_delete')->default(false);
            $table->boolean('can_print')->default(false);
            $table->boolean('can_history')->default(false);
            $table->json('custom_permissions')->nullable();
            $table->string('signature', 128)->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->foreign('system_resource_id')->references('id')->on('Au10_system_resources')->onDelete('cascade');
            $table->index(['permissionable_type', 'permissionable_id']);
            $table->index('system_resource_id');
            $table->unique(['permissionable_type', 'permissionable_id', 'system_resource_id'], 'au10_permissions_unique');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('Au10_permissions');
    }
};
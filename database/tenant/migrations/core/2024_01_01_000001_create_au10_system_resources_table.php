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
        Schema::create('au10_system_resources', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('parent_id')->nullable();
            $table->string('name');
            $table->string('identifier')->unique();
            $table->enum('type', ['model', 'function', 'module', 'page'])->default('model');
            $table->text('description')->nullable();
            $table->integer('menu_order')->default(0);
            $table->string('signature', 128)->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->foreign('parent_id')->references('id')->on('au10_system_resources')->onDelete('cascade');
            $table->index(['type', 'menu_order']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('au10_system_resources');
    }
};
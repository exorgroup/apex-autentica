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
        Schema::create('au10_groups', function (Blueprint $table) {
            $table->id();
            /* Plain, not unique: this table soft-deletes and a unique index does not
               know about `deleted_at`, so a deleted group would reserve its name for
               ever and re-creating it would 500 on the insert. Uniqueness among live
               rows is the validation rule's job (`whereNull('deleted_at')`). The
               `index('name')` below is what lookups use. */
            $table->string('name');
            $table->text('description')->nullable();
            $table->string('signature', 128)->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->index('name');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('au10_groups');
    }
};
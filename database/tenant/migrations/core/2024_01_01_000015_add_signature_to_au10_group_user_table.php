<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Group membership is a security-relevant fact — it is what grants a person their
     * permissions — so it carries a signature like every other Autentica row.
     *
     * The column exists whether or not signing is switched on. If it changed with the
     * setting, flipping APEX_SIGNATURE_ENABLED would break the application; instead the
     * column simply stays empty while signing is off.
     */
    public function up(): void
    {
        Schema::table('au10_group_user', function (Blueprint $table) {
            $table->string('signature', 128)->nullable()->after('assigned_by');
        });
    }

    public function down(): void
    {
        Schema::table('au10_group_user', function (Blueprint $table) {
            $table->dropColumn('signature');
        });
    }
};

<?php

namespace Apex\Autentica\Core\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * One suspension of one account — 0.3.0.
 *
 * Active while `lifted_at` is null. Never edited into a different suspension: lifting one
 * closes the row, and suspending again opens a new one, so the history reads straight.
 */
class AccountSuspension extends Model
{
    use SoftDeletes;

    protected $table = 'au10_account_suspensions';

    protected $fillable = ['user_id', 'suspended_by', 'reason', 'suspended_at', 'lifted_at', 'lifted_by'];

    protected $casts = [
        'suspended_at' => 'datetime',
        'lifted_at' => 'datetime',
    ];

    public function scopeActive(Builder $query): Builder
    {
        return $query->whereNull('lifted_at');
    }
}

<?php

namespace Apex\Autentica\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/** The smallest host user the suspension tests need. */
class User extends Authenticatable
{
    protected $table = 'users';

    protected $guarded = [];
}

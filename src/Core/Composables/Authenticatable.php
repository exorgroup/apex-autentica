<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Authenticatable composable trait that adds Autentica authentication features
 *              to the User model. Include this trait in your App\Models\User model.
 * URL: apex/autentica/src/Core/Composables/Authenticatable.php
 */

namespace Apex\Autentica\Core\Composables;

use Apex\Autentica\Core\Traits\HasPermissions;
use Apex\Autentica\Core\Traits\HasGroups;
use Apex\Autentica\Core\Traits\HasSecurityEvents;
use Apex\Autentica\Core\Traits\Signable;

trait Authenticatable
{
    use HasPermissions;
    use HasGroups;
    use HasSecurityEvents;
    use Signable;

    // The individual traits will boot automatically through Laravel's trait booting mechanism
    // No need to manually call boot methods
}

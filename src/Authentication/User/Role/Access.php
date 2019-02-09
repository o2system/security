<?php
/**
 * This file is part of the O2System Framework package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author         Steeve Andrian Salim
 * @copyright      Copyright (c) Steeve Andrian Salim
 */

// ------------------------------------------------------------------------

namespace O2System\Security\Authentication\User\Role;

// ------------------------------------------------------------------------

/**
 * Class Access
 * @package O2System\Security\Authentication\User\Role
 */
class Access
{
    const PERMISSION_GRANTED = true;
    const PERMISSION_DENIED = false;

    protected $permission = false;

    protected $privileges = [
        'create'  => false,
        'read'    => false,
        'update'  => false,
        'delete'  => false,
        'import'  => false,
        'export'  => false,
        'print'   => false,
        'special' => false,
    ];
}
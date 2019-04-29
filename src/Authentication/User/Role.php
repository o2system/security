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

namespace O2System\Security\Authentication\User;

// ------------------------------------------------------------------------

use O2System\Spl\Patterns\Structural\Repository\AbstractRepository;

/**
 * Class Role
 * @package O2System\Security\Authentication\User
 */
class Role extends AbstractRepository
{
    public function __construct(array $role)
    {
        foreach ($role as $key => $value) {
            $this->store($key, $value);
        }
    }
}
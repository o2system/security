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

namespace O2System\Security\Authentication\Oauth;

// ------------------------------------------------------------------------

use O2System\Psr\Patterns\Structural\Repository\AbstractRepository;

/**
 * Class User
 * @package O2System\Security\Authentication\Oauth\Resource\Request
 */
class User extends AbstractRepository
{
    /**
     * User::__construct
     *
     * @param array $account
     */
    public function __construct(array $account)
    {
        foreach ($account as $offset => $value) {
            $this->store($offset, $value);
        }
    }
}
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

namespace O2System\Security\Authentication\Oauth\Client;

// ------------------------------------------------------------------------

use O2System\Spl\Patterns\Structural\Repository\AbstractRepository;

/**
 * Class Account
 * @package O2System\Security\Authentication\Oauth\Client
 */
class Account extends AbstractRepository
{
    /**
     * Account::__construct
     *
     * @param array $account
     */
    public function __construct(array $account)
    {
        foreach ($account as $key => $value) {
            if (strpos($key, 'record') === false &&
                ! in_array($key, ['password', 'pin', 'token', 'sso'])) {
                $this->store($key, $value);
            }
        }
    }
}
<?php
/**
 * This file is part of the O2System PHP Framework package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author         Steeve Andrian Salim
 * @copyright      Copyright (c) Steeve Andrian Salim
 */
// ------------------------------------------------------------------------

namespace O2System\Security\Access\User;

// ------------------------------------------------------------------------

/**
 * Class Registration
 *
 * @package O2System\Security\Access\User
 */
class Registration
{
    /**
     * Registration::$account
     *
     * @var \O2System\Security\Access\User\Account
     */
    protected $account;

    // ------------------------------------------------------------------------

    /**
     * Registration::__construct
     *
     * @param array|Account|null $account
     */
    public function __construct ( $account  = null )
    {
        if( is_array( $account ) ) {
            $this->account = new Account( $account );
        } elseif( $account instanceof Account ) {
            $this->account = $account;
        }
    }
}
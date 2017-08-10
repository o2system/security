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

namespace O2System\Security\Access;

// ------------------------------------------------------------------------
/**
 * Class User
 *
 * @package O2System\Security\Access
 */
class User
{
    /**
     * login
     *
     * @param      $account
     * @param      $password
     * @param bool $remember
     */
    public function login ( $account, $password, $remember = false )
    {
        /**
         * This code will benchmark your server to determine how high of a cost you can
         * afford. You want to set the highest cost that you can without slowing down
         * you server too much. 8-10 is a good baseline, and more is good if your servers
         * are fast enough. The code below aims for ≤ 50 milliseconds stretching time,
         * which is a good baseline for systems handling interactive logins.
         */
        $cost = 8;

        do {
            $cost++;
            $start = microtime( true );
            password_hash( $password, PASSWORD_BCRYPT, [ 'cost' => $cost ] );
            $end = microtime( true );
        }
        while ( ( $end - $start ) < 0.05 ); // 50 milliseconds

        if ( password_verify( $password, $account->password ) ) {
            if ( password_needs_rehash( $account->password, PASSWORD_BCRYPT, [ 'cost' => $cost ] ) ) {
                // If so, create a new hash, and replace the old one
                $account->password = password_hash( $password, PASSWORD_BCRYPT, [ 'cost' => $cost ] );
            }

            if ( function_exists( 'session' ) ) {
                session()->set( 'account', $account );
            }
        }
    }

    public function register()
    {
        print_out('test');
    }

    public function logout ()
    {

    }

    public function getAccount ()
    {

    }

    public function updateAccount ()
    {

    }

    public function isLogin ()
    {

    }
}
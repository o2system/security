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

namespace O2System\Security\Access\Datastructures;


use O2System\Spl\Datastructures\SplArrayObject;

class UserData extends SplArrayObject
{
    public function __construct ( array $userdata = [ ] )
    {
        parent::__construct(
            array_merge(
                [
                    'username' => null,
                    'password' => null,
                    'salt'     => null,
                    'email'    => null,
                    'msisdn'   => null,
                ],
                $userdata
            )
        );

        if ( null !== ( $username = $this->offsetGet( 'username' ) ) and
             null !== ( $password = $this->offsetGet( 'username' ) )
        ) {
            $this->getSalt( $username, $password );
        }
    }

    public function getSalt ( $username, $password )
    {

    }
}
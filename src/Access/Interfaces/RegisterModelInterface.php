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

namespace O2System\Security\Access\Interfaces;


use O2System\Security\Access\Datastructures\UserData;

interface RegisterModelInterface
{
    public function insertRegistrationData ( UserData $userdata );

    public function updateRegistrationData ( UserData $userdata );

    public function isUsernameExists ( $username );

    public function isEmailExists ( $email );

    public function isMsisdnExists ( $msisdn );
}
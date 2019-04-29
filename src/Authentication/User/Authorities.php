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

use O2System\Spl\Patterns\Structural\Provider\AbstractProvider;
use O2System\Spl\Patterns\Structural\Provider\ValidationInterface;

/**
 * Class Authorities
 * @package O2System\Security\Authentication\User
 */
class Authorities extends AbstractProvider implements ValidationInterface
{
    /**
     * Authorities::validate
     *
     * Checks if the object is a valid instance.
     *
     * @param object $object The object to be validated.
     *
     * @return bool Returns TRUE on valid or FALSE on failure.
     */
    public function validate($object)
    {
        if ($object instanceof Authority) {
            return true;
        }

        return false;
    }

    public function authorize($segments)
    {
        if ($authority = $this->getAuthority($segments)) {
            return $authority->getPermission() === 'GRANTED' ? true : false;
        }

        return false;
    }

    public function getAuthority($segments)
    {
        $segments = is_array($segments) ? implode('/', $segments) : $segments;

        if ($this->exists($segments)) {
            if (($authority = $this->getObject($segments)) instanceof Authority) {
                return $authority;
            }
        }

        return false;
    }
}
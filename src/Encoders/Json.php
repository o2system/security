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

namespace O2System\Security\Encoders;

// ------------------------------------------------------------------------

use O2System\Spl\DataStructures\SplArrayObject;

/**
 * Class Json
 * @package O2System\Security\Encoders
 */
class Json
{
    public static function encode($string)
    {
        $json = json_encode($string);
        if (JSON_ERROR_NONE === json_last_error()) {
            return $json;
        }

        return null;
    }

    // ------------------------------------------------------------------------

    public static function decode($string)
    {
        $json = json_decode($string, true);
        if (JSON_ERROR_NONE === json_last_error()) {
            return new SplArrayObject($json);
        }

        return null;
    }
}
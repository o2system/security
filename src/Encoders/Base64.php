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

/**
 * Class Base64
 * @package O2System\Security\Encoders
 */
class Base64
{
    /**
     * Base64::encode
     *
     * Encrypt a string with URL-Safe Base64.
     *
     * @param $string
     *
     * @return string
     */
    public static function encode($string)
    {
        return str_replace(['+', '/', '\r', '\n', '='],
            ['-', '_'],
            base64_encode($string));
    }

    // ------------------------------------------------------------------------

    /**
     * Base64::decode
     *
     * Decrypt a string with URL-Safe Base64.
     *
     * @param $string
     *
     * @return bool|string
     */
    public static function decode($string)
    {
        return base64_decode(str_replace(['-', '_'],
            ['+', '/'],
            $string));
    }
}
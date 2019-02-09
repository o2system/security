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

namespace O2System\Security\Encryptions;

// ------------------------------------------------------------------------

/**
 * Class Hmac
 * @package O2System\Security\Encryptions
 */
class Hmac
{
    /**
     * Hmac::hash
     *
     * Generate a keyed hash value using the HMAC method.
     *
     * @param string              $algo
     * @param string|array|object $data
     * @param string              $key
     * @param bool                $rawOutput
     *
     * @return string
     */
    public static function hash($algo, $data, $key, $rawOutput = false)
    {
        if (is_array($data) || is_object($data)) {
            $data = serialize($data);
        }

        if (strpos($algo, 'HMAC-') !== false) {
            $algo = str_replace('HMAC-', '', $algo);
            $algo = strtolower($algo);
        }

        return hash_hmac($algo, $data, $key, $rawOutput);
    }
}
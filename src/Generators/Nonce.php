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

namespace O2System\Security\Generators;

// ------------------------------------------------------------------------

use O2System\Security\Encryptions\Algorithm;
use O2System\Security\Encryptions\Hmac;

/**
 * Class Nonce
 * @package O2System\Security\Authentication\Oauth
 */
class Nonce
{
    /**
     * Nonce::generate
     *
     * @param string $algorithm
     *
     * @return bool|string
     */
    public static function generate($algorithm = 'HMAC-SHA1')
    {
        $data = microtime() . mt_rand();
        $key = time();

        if (Algorithm::validate($algorithm)) {
            list($function, $algorithm) = Algorithm::map($algorithm);

            switch ($function) {
                case 'HMAC':
                    return Hmac::hash($algorithm, $data, $key);
                case 'hash_hmac':
                    return hash_hmac($algorithm, $data, $key);
                case 'openssl':
                    return openssl_sign($data, $signature, $key, $algorithm);
            }
        }
    }
}
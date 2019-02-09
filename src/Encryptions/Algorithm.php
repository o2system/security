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
 * Class Algorithm
 * @package O2System\Security\Encryptions
 */
class Algorithm
{
    public static $supported = [
        'HS1'         => ['hash_hmac', 'sha1'],
        'HS256'       => ['hash_hmac', 'sha256'],
        'HS512'       => ['hash_hmac', 'sha512'],
        'HS384'       => ['hash_hmac', 'sha384'],
        'HMAC-SHA1'   => ['HMAC', 'sha1'],
        'HMAC-SHA256' => ['HMAC', 'sha256'],
        'HMAC-SHA512' => ['HMAC', 'sha512'],
        'HMAC-SHA384' => ['HMAC', 'sha384'],
        'RS1'         => ['openssl', OPENSSL_ALGO_SHA1],
        'RS256'       => ['openssl', OPENSSL_ALGO_SHA256],
        'RS384'       => ['openssl', OPENSSL_ALGO_SHA384],
        'RS512'       => ['openssl', OPENSSL_ALGO_SHA512],
    ];

    // ------------------------------------------------------------------------

    /**
     * Algorithm::validate
     *
     * Validate algorithm
     *
     * @param string $algorithm
     *
     * @return bool
     */
    public static function validate($algorithm)
    {
        $algorithm = strtoupper($algorithm);

        return (bool)array_key_exists($algorithm, static::$supported);
    }

    // ------------------------------------------------------------------------

    /**
     * Algorithm::map
     *
     * Gets algorithm map.
     *
     * @param string $algorithm
     *
     * @return array
     */
    public static function map($algorithm)
    {
        return static::$supported[ $algorithm ];
    }
}
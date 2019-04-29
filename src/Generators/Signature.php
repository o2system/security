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
 * Class Signature
 * @package O2System\Security\Generators
 */
class Signature
{
    /**
     * Signature::generate
     *
     * @param array  $segments
     * @param string $key
     * @param string $algorithm
     *
     * @return bool|string
     * @throws \O2System\Spl\Exceptions\Logic\DomainException
     */
    public static function generate(array $segments, $key, $algorithm = 'HS256')
    {
        if (count($segments) == 2) {
            $data = implode('.', $segments);

            if (Algorithm::validate($algorithm)) {
                list($function, $algorithm) = Algorithm::map($algorithm);

                switch ($function) {
                    case 'HMAC':
                        return Hmac::hash($algorithm, $data, $key, true);
                    case 'hash_hmac':
                        return hash_hmac($algorithm, $data, $key, true);
                    case 'openssl':
                        return openssl_sign($data, $signature, $key, $algorithm);
                }
            }
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Signature::verify
     *
     * Verify token with signature.
     *
     * @param string $token
     * @param string $signature
     * @param string $key
     * @param string $algorithm
     *
     * @return bool
     */
    public static function verify($token, $signature, $key, $algorithm = 'HS256')
    {
        $segments = explode('.', $token);
        $segments = array_map('trim', $segments);

        if (count($segments) == 3) {
            array_pop($segments);
            $data = implode('.', $segments);

            if (Algorithm::validate($algorithm)) {
                list($function, $algorithm) = Algorithm::map($algorithm);

                switch ($function) {
                    case 'HMAC':
                        return Hmac::hash($algorithm, $data, $key, true) === $signature;
                    case 'hash_hmac':
                        return hash_hmac($algorithm, $data, $key, true) === $signature;
                    case 'openssl':
                        switch ($algorithm) {
                            case 'RS256':
                                return (bool)openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA1);
                            case 'RS256':
                                return (bool)openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA256);
                            case 'RS384':
                                return (bool)openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA384);
                            case 'RS512':
                                return (bool)openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA512);
                        }
                }
            }
        }

        return false;
    }
}
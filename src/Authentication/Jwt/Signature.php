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

namespace O2System\Security\Authentication\Jwt;

// ------------------------------------------------------------------------
use O2System\Spl\Exceptions\Logic\DomainException;

/**
 * Class Signature
 * @package O2System\Security\Generators
 */
class Signature
{
    public static $supportedAlgorithms = [
        'HS256' => ['hash_hmac', 'sha256'],
        'HS512' => ['hash_hmac', 'sha512'],
        'HS384' => ['hash_hmac', 'sha384'],
        'RS256' => ['openssl', OPENSSL_ALGO_SHA256],
        'RS384' => ['openssl', OPENSSL_ALGO_SHA384],
        'RS512' => ['openssl', OPENSSL_ALGO_SHA512],
    ];

    public static function validAlgorithm($algorithm)
    {
        $algorithm = strtoupper($algorithm);

        return (bool)array_key_exists($algorithm, static::$supportedAlgorithms);
    }

    public static function generate(array $segments, $key, $algorithm = 'HS256')
    {
        if (count($segments) == 2) {
            $data = implode('.', $segments);

            if (static::validAlgorithm($algorithm)) {
                list($function, $algorithm) = static::$supportedAlgorithms[ $algorithm ];

                switch ($function) {
                    case 'hash_hmac':
                        return hash_hmac($algorithm, $data, $key, true);
                    case 'openssl':
                        if (false === ($success = openssl_sign($data, $signature, $key, $algorithm))) {
                            throw new DomainException("OpenSSL unable to sign data");
                        }
                }
            }
        }

        return false;
    }

    public static function verify($token, $signature, $key, $algorithm = 'HS256')
    {
        $segments = explode('.', $token);
        $segments = array_map('trim', $segments);

        if (count($segments) == 3) {
            array_pop($segments);
            $data = implode('.', $segments);

            if (static::validAlgorithm($algorithm)) {
                list($function, $algorithm) = static::$supportedAlgorithms[ $algorithm ];

                switch ($function) {
                    case 'hash_hmac':
                        return hash_hmac($algorithm, $data, $key, true) === $signature;
                    case 'openssl':
                        switch ($algorithm) {
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
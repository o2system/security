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

namespace O2System\Security\Authentication\Oauth;

// ------------------------------------------------------------------------

/**
 * Class Nonce
 * @package O2System\Security\Authentication\Oauth
 */
class Nonce
{
    public static function generate($signatureMethod = OAUTH_SIG_METHOD_HMACSHA1)
    {
        switch ($signatureMethod) {
            default:
            case OAUTH_SIG_METHOD_HMACSHA1:
            case OAUTH_SIG_METHOD_RSASHA1:

                $algo = 'sha1';
                break;

            case OAUTH_SIG_METHOD_HMACSHA256:

                $algo = 'sha256';
                break;
        }

        return hash_hmac($algo, microtime() . mt_rand(), time());
    }
}
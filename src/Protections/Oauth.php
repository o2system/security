<?php
/**
 * Created by PhpStorm.
 * User: steevenz
 * Date: 13/03/18
 * Time: 16.02
 */

namespace O2System\Security\Protections;


class Oauth
{
    const VERSION = '1.0';

    public static function generateNonce($signatureMethod = OAUTH_SIG_METHOD_HMACSHA1)
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

    public static function generateConsumer($signatureMethod = OAUTH_SIG_METHOD_HMACSHA1)
    {
        do {
            $entropy = openssl_random_pseudo_bytes(32, $strong);
        } while ($strong === false);

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

        $hash = hash_hmac($algo, $entropy, time());

        // The first 30 bytes should be plenty for the consumer_key
        // We use the last 10 for the shared secret
        return [
            'key' => $key = substr($hash, 0, 32),
            'secret' => md5($key)
        ];
    }
}
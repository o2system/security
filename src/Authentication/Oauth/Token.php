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

namespace O2System\Security\Authentication\Oauth;

// ------------------------------------------------------------------------

use O2System\Psr\Http\Server\MethodInterface;
use O2System\Security\Encoders\Base64;
use O2System\Security\Encoders\Json;
use O2System\Security\Generators\Signature;
use O2System\Spl\Traits\Collectors\ErrorCollectorTrait;

/**
 * Class Token
 * @package O2System\Security\Authentication\Oauth
 */
class Token implements MethodInterface
{
    use ErrorCollectorTrait;

    protected $consumer;

    public function __construct(Consumer $consumer)
    {
        $this->consumer = $consumer;
    }

    // ------------------------------------------------------------------------

    /**
     * Token::getVerifier
     *
     * Gets Token oauth_verifier code.
     *
     * @return bool|string
     */
    public function getVerifier()
    {
        if ( ! empty($this->key) && ! empty($this->secret)) {
            $key = rawurlencode($this->key);
            $secret = rawurlencode($this->secret);

            return base64_encode($key . ':' . $secret);
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Token::getRequest
     *
     * Gets OAuth Request Token.
     *
     * @return array|bool Returns FALSE if failed.
     */
    public function getRequest($callbackUrl, $httpMethod = self::HTTP_POST)
    {
        $algorithm = 'HMAC-SHA1';
        if (false === ($signature = Base64::decode($this->consumer->secret))) {
            $this->addError(400, 'Invalid Consumer Secret');

            return false;
        }

        if (false === ($signature = Json::decode($signature))) {
            $this->addError(400, 'Invalid Consumer Secret');

            return false;
        }

        $signature->callbackUrl = $callbackUrl;
        $signature->httpMethod = $httpMethod;
        $algorithm = $signature->algorithm;

        if (false !== ($payload = Base64::decode($this->consumer->key))) {
            $payload = Json::decode($payload)->getArrayCopy();
        }

        if ($payload) {
            $payload[ 'timestamp' ] = time();

            $segments[] = Base64::encode(Json::encode($signature));
            $segments[] = $token = Base64::encode(Signature::generate([
                'payload' => Base64::encode(Json::encode($payload)),
                'token'   => \OAuthProvider::generateToken(strlen($this->consumer->secret), true),
            ], $this->consumer->key, $algorithm));

            $secret = Base64::encode(Signature::generate($segments, $this->consumer->key, $algorithm));

            return [
                'oauth_token'        => $token,
                'oauth_token_secret' => $secret,
            ];
        }

        return false;
    }

    // ------------------------------------------------------------------------
}
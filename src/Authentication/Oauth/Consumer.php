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
use O2System\Security\Generators;
use O2System\Spl\Traits\Collectors\ErrorCollectorTrait;

/**
 * Class Consumer
 * @package O2System\Security\Authentication\Oauth
 */
class Consumer implements MethodInterface
{
    use ErrorCollectorTrait;

    public $version = '1.0';

    /**
     * Consumer::$key
     *
     * String of OAuth Consumer Key (oauth_consumer_key).
     *
     * @var string
     */
    public $key;

    /**
     * Consumer::$secret
     *
     * String of OAuth Consumer Secret (oauth_consumer_secret).
     *
     * @var string
     */
    public $secret;

    /**
     * Consumer::__construct
     *
     * @param string $key    oauth_consumer_key.
     * @param string $secret oauth_consumer_secret.
     */
    public function __construct($key, $secret)
    {
        $this->setKey($key);
        $this->setSecret($secret);
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::setKey
     *
     * Sets oauth_consumer_key.
     *
     * @param string $key oauth_consumer_key.
     *
     * @return static
     */
    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::setSecret
     *
     * Sets oauth_consumer_secret.
     *
     * @param string $secret oauth_consumer_secret.
     *
     * @return static
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::generate
     *
     * Generate consumer secret and key base on payload.
     *
     * @param array $payload
     *
     * @return array
     */
    public static function generate(array $payload, $algorithm = 'HMAC-SHA1')
    {
        $token = new Generators\Token();
        $token->setAlgorithm($algorithm);
        $token->addHeader('timestamp', time());

        $tokenString = $token->encode($payload);
        $tokenParts = explode('.', $tokenString);
        $tokenParts = array_map('trim', $tokenParts);

        return [
            'oauth_consumer_key'    => $tokenParts[ 1 ],
            'oauth_consumer_secret' => $tokenParts[ 0 ],
        ];
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::setVersion
     *
     * Sets oauth_version to 1.0 or 2.0
     *
     * @param string $version
     *
     * @return static
     */
    public function setVersion($version)
    {
        $this->version = in_array($version, ['1.0', '2.0']) ? $version : '1.0';

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::getRequestToken
     *
     * Fetch a request token, secret and any additional response parameters from the service provider.
     *
     * @param \O2System\Security\Authentication\Oauth\Consumer $consumer
     * @param string                                           $callbackUrl
     * @param string                                           $httpMethod
     *
     * @return array|bool Returns FALSE if failed.
     */
    public function getRequestToken($callbackUrl, $httpMethod = self::HTTP_POST)
    {
        $token = new Token($this);

        return $token->getRequest($callbackUrl, $httpMethod);
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::getAuthorizationHeader
     *
     * Gets OAuth HTTP_AUTHORIZATION header parameters.
     *
     * @param string|null $callbackUrl
     * @param string      $httpMethod
     *
     * @return string|bool Returns FALSE if failed
     */
    public function getAuthorizationHeader($callbackUrl, $httpMethod = self::HTTP_GET)
    {
        $algorithm = 'HMAC-SHA1';
        if (false === ($signature = Base64::decode($this->secret))) {
            $this->addError(400, 'Invalid Consumer Secret');

            return false;
        }

        if (false === ($signature = Json::decode($signature))) {
            $this->addError(400, 'Invalid Consumer Secret');

            return false;
        }

        $algorithm = $signature->algorithm;

        $oauth = new \OAuth($this->key, $this->secret, $algorithm, OAUTH_AUTH_TYPE_AUTHORIZATION);

        $parameters = [
            'oauth_nonce'            => Generators\Nonce::generate($algorithm),
            'oauth_callback'         => $callbackUrl,
            'oauth_signature_method' => $algorithm,
            'oauth_timestamp'        => time(),
            'oauth_consumer_key'     => $this->key,
        ];

        $parameters[ 'oauth_signature' ] = $oauth->generateSignature($httpMethod, $callbackUrl, $parameters);
        $parameters[ 'oauth_version' ] = $this->version;

        $parts = [];
        foreach ($parameters as $key => $value) {
            $parts[] = $key . '="' . $value . '"';
        }

        return 'OAuth ' . implode(', ', $parts);
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::getAuthorizationBasic
     *
     * Gets Consumer HTTP_AUTHORIZATION Bearer code.
     *
     * @return bool|string
     */
    public function getAuthorizationBasic()
    {
        if ( ! empty($this->key) && ! empty($this->secret)) {
            $key = rawurlencode($this->key);
            $secret = rawurlencode($this->secret);

            return 'Basic ' . base64_encode($key . ':' . $secret);
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::getAuthorizationBearer
     *
     * Gets Consumer HTTP_AUTHORIZATION Bearer code.
     *
     * @return bool|string
     */
    public function getAuthorizationBearer()
    {
        if ( ! empty($this->key) && ! empty($this->secret)) {
            $key = rawurlencode($this->key);
            $secret = rawurlencode($this->secret);

            return 'Bearer ' . base64_encode($key . ':' . $secret . ':' . md5($key . $secret));
        }

        return false;
    }
}
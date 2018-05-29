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

namespace O2System\Security\Protections\Oauth;

// ------------------------------------------------------------------------

/**
 * Class Consumer
 * @package O2System\Security\Protections\Oauth
 */
class Consumer
{
    /**
     * Consumer::$key
     *
     * String of OAuth Consumer Key (oauth_consumer_key).
     *
     * @var string
     */
    protected $key;

    /**
     * Consumer::$secret
     *
     * String of OAuth Consumer Secret (oauth_consumer_secret).
     *
     * @var string
     */
    protected $secret;

    /**
     * Consumer::$callbackUrl
     *
     * OAuth Callback Url (oauth_callback).
     *
     * @var string
     */
    protected $callbackUrl;

    // ------------------------------------------------------------------------

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
     * Consumer::setCallbackUrl
     *
     * Sets oauth_callback
     *
     * @param string $callbackUrl oauth_callback.
     *
     * @return static
     */
    public function setCallbackUrl($callbackUrl)
    {
        $this->callbackUrl = $callbackUrl;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::getAuthorizationHeader
     *
     * Gets OAuth HTTP_AUTHORIZATION header parameters.
     *
     * @param string|null $httpUrl
     * @param string      $httpMethod
     *
     * @return string
     */
    public function getAuthorizationHeader($httpUrl = null, $httpMethod = 'GET')
    {
        $signatureMethod = OAUTH_SIG_METHOD_HMACSHA1;

        $parameters = [
            'oauth_nonce'            => Oauth::generateNonce(),
            'oauth_signature_method' => $signatureMethod,
            'oauth_timestamp'        => time(),
            'oauth_consumer_key'     => $this->key,
            'oauth_version'          => Oauth::VERSION,
        ];

        if (isset($httpUrl)) {
            $parameters[ 'oauth_signature' ] = $this->getSignature($signatureMethod, $httpUrl, $httpMethod,
                $parameters);
        } else {
            $parameters[ 'oauth_signature' ] = $this->getSignature($signatureMethod, null, null,
                $parameters);
        }

        if ( ! empty($this->callbackUrl)) {
            $parameters[ 'callback' ] = $this->callbackUrl;
        }

        foreach ($parameters as $key => $value) {
            $parts[] = $key . '="' . $value . '"';
        }

        return 'OAuth ' . implode(', ', $parts);
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::getSignature
     *
     * Gets OAuth Consumer Signature.
     *
     * @param string      $signatureMethod
     * @param string|null $httpUrl
     * @param string|null $httpMethod
     * @param array       $parameters
     *
     * @return string
     */
    public function getSignature(
        $signatureMethod = OAUTH_SIG_METHOD_HMACSHA1,
        $httpUrl = null,
        $httpMethod = OAUTH_HTTP_METHOD_GET,
        array $parameters = []
    ) {
        if (isset($httpUrl)) {
            $urlParts = parse_url($httpUrl);
            $scheme = $urlParts[ 'scheme' ];
            $host = strtolower($urlParts[ 'host' ]);
            $path = $urlParts[ 'path' ];
            $httpUrl = "$scheme://$host$path";

            $parts = [
                rawurlencode(strtoupper($httpMethod)),
                rawurlencode($httpUrl),
                rawurlencode(http_build_query($parameters, null, null, PHP_QUERY_RFC3986)),
            ];
        } else {
            $parts = [
                rawurlencode(http_build_query($parameters, null, null, PHP_QUERY_RFC3986)),
            ];
        }

        $signatureBaseString = implode('&', $parts);

        switch ($signatureMethod) {
            default:
            case OAUTH_SIG_METHOD_HMACSHA1:
            case OAUTH_SIG_METHOD_RSASHA1:

                return hash_hmac('sha1', $signatureBaseString, $this->secret);
                break;

            case OAUTH_SIG_METHOD_HMACSHA256:

                return hash_hmac('sha256', $signatureBaseString, $this->secret);
                break;
        }
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
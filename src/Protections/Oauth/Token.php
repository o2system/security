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
 * Class Token
 * @package O2System\Security\Protections\Oauth
 */
class Token
{
    /**
     * Token::$key
     *
     * String of OAuth Token (oauth_token).
     *
     * @var string
     */
    protected $key;

    /**
     * Token::$secret
     *
     * String of OAuth Token Secret (oauth_token_secret).
     *
     * @var string
     */
    protected $secret;

    // ------------------------------------------------------------------------

    /**
     * Token::__construct
     *
     * @param string $key    oauth_token.
     * @param string $secret oauth_token_secret.
     */
    public function __construct($key, $secret)
    {
        $this->setKey($key);
        $this->setSecret($secret);
    }

    // ------------------------------------------------------------------------

    /**
     * Token::setKey
     *
     * Sets oauth_token.
     *
     * @param string $key oauth_token.
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
     * Token::setSecret
     *
     * Sets oauth_token_secret.
     *
     * @param string $secret oauth_token_secret.
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
}
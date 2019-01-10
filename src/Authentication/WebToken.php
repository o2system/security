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

namespace O2System\Security\Authentication;

// ------------------------------------------------------------------------

/**
 * Class TokenAuthentication
 *
 * @package O2System\Security\Authentication
 */
class WebToken
{
    /**
     * TokenAuthentication::$token
     *
     * X-WEB-TOKEN protection token.
     *
     * @var string
     */
    private $token;

    // ------------------------------------------------------------------------

    /**
     * TokenAuthentication::setToken
     *
     * Sets X-WEB-TOKEN protection token.
     *
     * @param string $token X-WEB-TOKEN protection token.
     *
     * @return static
     */
    public function setToken($token)
    {
        $_SESSION[ 'X-WEB-TOKEN' ] = $this->token = $token;
        header('X-WEB-TOKEN: ' . $this->token);

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * TokenAuthentication::getToken
     *
     * Gets X-WEB-TOKEN protection token.
     *
     * @return string|bool Returns FALSE if X-WEB-TOKEN protection token is not set.
     */
    public function getToken()
    {
        if (isset($_SESSION[ 'X-WEB-TOKEN' ])) {
            return $_SESSION[ 'X-WEB-TOKEN' ];
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * TokenAuthentication::verify
     *
     * Checks if the posted X-WEB-TOKEN protection token is valid.
     *
     * @param string $token X-WEB-TOKEN protection token.
     *
     * @return bool
     */
    public function verify($token = null)
    {
        $token = isset($token)
            ? $token
            : input()->server('HTTP_X_WEB_TOKEN');

        if(is_null($token)) {
            return false;
        } elseif(false !== ($verifierToken = $this->getToken())) {
            return hash_equals($verifierToken, $token);
        }

        return false;
    }
}
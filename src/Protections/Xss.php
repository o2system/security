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

namespace O2System\Security\Protections;

// ------------------------------------------------------------------------

/**
 * Class Xss
 *
 * @package O2System\Security\Protections
 */
class Xss
{
    /**
     * Xss::$token
     *
     * Active XSS protection token.
     *
     * @var string
     */
    private $token;

    // ------------------------------------------------------------------------

    /**
     * Xss::__construct
     */
    public function __construct()
    {
        if (false === ($this->token = $this->getToken())) {
            $this->regenerate();
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Xss::getToken
     *
     * Gets session XSS protection token.
     *
     * @return string|bool Returns FALSE if XSS protection token is not set.
     */
    public function getToken()
    {
        if (isset($_SESSION[ 'xssToken' ])) {
            return $_SESSION[ 'xssToken' ];
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Xss::regenerate
     *
     * Regenerate CSRF protection token.
     *
     * @return void
     */
    public function regenerate()
    {
        $_SESSION[ 'xssToken' ] = $this->token = 'XSS-' . bin2hex(random_bytes(32));
    }

    // ------------------------------------------------------------------------

    /**
     * Xss::verify
     *
     * Checks if the posted XSS protection token is valid.
     *
     * @param string $token
     *
     * @return bool
     */
    public function verify($token = null)
    {
        $token = isset($token)
            ? $token
            : input()->postGet('xssToken');

        if (is_string($token)) {
            return hash_equals($this->getToken(), $token);
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Xss::clean
     *
     * @return mixed
     */
    public function clean($string)
    {
        return \O2System\Security\Filters\Xss::clean($string);
    }
}
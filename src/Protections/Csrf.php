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

namespace O2System\Security\Protections;

// ------------------------------------------------------------------------

/**
 * Class Csrf
 *
 * @package O2System\Security\Protections
 */
class Csrf
{
    /**
     * Csrf::$token
     *
     * Active CSRF protection token.
     *
     * @var string
     */
    private $token;

    // ------------------------------------------------------------------------

    /**
     * Csrf::__construct
     */
    public function __construct()
    {
        if (false === ($this->token = $this->getToken())) {
            $this->regenerate();
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Csrf::getToken
     *
     * Gets session CSRF protection token.
     *
     * @return string|bool Returns FALSE if CSRF protection token is not set.
     */
    public function getToken()
    {
        if (isset($_SESSION[ 'csrfToken' ])) {
            return $_SESSION[ 'csrfToken' ];
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Csrf::regenerate
     *
     * Regenerate CSRF protection token.
     *
     * @return void
     */
    public function regenerate()
    {
        $_SESSION[ 'csrfToken' ] = $this->token = md5(uniqid(mt_rand(), true) . 'CSRF');
    }

    // ------------------------------------------------------------------------

    /**
     * Csrf::verify
     *
     * Checks if the posted CSRF protection token is valid.
     *
     * @param string $token
     *
     * @return bool
     */
    public function verify($token = null)
    {
        $token = isset($token)
            ? $token
            : input()->postGet('csrfToken');

        if (false !== ($this->getToken() === $token)) {
            return true;
        }

        return false;
    }
}
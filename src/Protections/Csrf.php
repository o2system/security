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


class Csrf
{
    /**
     * Is Enabled Flag
     *
     * @var bool
     */
    private $isEnabled = false;

    /**
     * CSRF Token
     *
     * @var string
     */
    private $token;

    // ------------------------------------------------------------------------

    /**
     * Initialize CSRF Security Protection
     */
    public function initialize ()
    {
        if ( false === ( $this->token = $this->getToken() ) ) {
            $this->regenerate();
        }

        $this->isEnabled = true;
    }

    // ------------------------------------------------------------------------

    /**
     * Get Token
     *
     * @return array|bool|null
     */
    public function getToken ()
    {
        if ( isset( $_SESSION[ 'csrfToken' ] ) ) {
            return $_SESSION[ 'csrfToken' ];
        }

        return false;
    }

    /**
     * Regenerate
     *
     * Regenerate CSRF Token
     */
    public function regenerate ()
    {
        $_SESSION[ 'csrfToken' ] = $this->token = md5( uniqid( mt_rand(), true ) . 'CSRF' );
    }

    // ------------------------------------------------------------------------

    /**
     * Validate Token
     *
     * @param string $token
     *
     * @return bool
     */
    public function validateToken ( $token )
    {
        if ( false !== ( $this->getToken() === $token ) ) {
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Is Enabled
     *
     * Check whether CSRF is enabled
     *
     * @return bool
     */
    public function isEnabled ()
    {
        return (bool) $this->isEnabled;
    }
}
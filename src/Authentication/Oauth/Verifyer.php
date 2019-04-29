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

/**
 * Class Verifyer
 * @package O2System\Security\Authentication\Oauth\Client
 */
class Verifyer
{
    /**
     * Verifyer::$callback
     *
     * @var \Closure
     */
    protected $callback;

    // ------------------------------------------------------------------------

    /**
     * Verifyer::setCallback
     *
     * @param \Closure $callback
     *
     * @return static
     */
    public function setCallback(\Closure $callback)
    {
        $this->callback = $callback;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Verifyer::verify
     *
     * @param array $data
     *
     * @return bool
     */
    public function verify(array $data)
    {
        if (is_callable($this->callback)) {
            return call_user_func($this->callback, $data);
        }

        return false;
    }
}
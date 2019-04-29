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

namespace O2System\Security\Authentication;

// ------------------------------------------------------------------------

/**
 * Class WebToken
 *
 * @package O2System\Security\Authentication
 */
class WebToken
{
    /**
     * WebToken::verify
     *
     * Checks if the posted X-WEB-TOKEN protection token is valid.
     *
     * @param string   $token    X-WEB-TOKEN protection token.
     * @param \Closure $callback Callback verification process.
     *
     * @return bool
     */
    public function verify($token = null, \Closure $callback)
    {
        $token = isset($token)
            ? $token
            : input()->server('HTTP_X_WEB_TOKEN');

        if (is_null($token)) {
            return false;
        } elseif (is_callable($callback)) {
            return call_user_func($callback, $token);
        }

        return false;
    }
}
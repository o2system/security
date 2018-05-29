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

namespace O2System\Security\Protections\Oauth\Datastructures;

// ------------------------------------------------------------------------

use O2System\Spl\Datastructures\SplArrayObject;

/**
 * Class Token
 * @package O2System\Security\Protections\Oauth\Datastructures
 */
class Token extends SplArrayObject
{
    /**
     * Token::__construct
     *
     * @param array $token
     */
    public function __construct(array $token = [])
    {
        parent::__construct(array_merge([
            'key'    => null,
            'secret' => null,
            'type'   => 'Bearer',
        ], $token));
    }

    // ------------------------------------------------------------------------

    /**
     * Token::__toString
     *
     * Generates the basic string serialization of a token that a server
     * would respond to request_token and access_token calls with
     *
     * @return string
     */
    public function __toString()
    {
        return sprintf("oauth_token=%s&oauth_token_secret=%s",
            rawurlencode($this->key),
            rawurlencode($this->secret)
        );
    }
}
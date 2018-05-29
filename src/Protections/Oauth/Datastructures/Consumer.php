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
 * Class Consumer
 * @package O2System\Security\Protections\Oauth\Datastructures
 */
class Consumer extends SplArrayObject
{
    /**
     * Consumer::__construct
     *
     * @param array $consumer
     */
    public function __construct(array $consumer = [])
    {
        parent::__construct(array_merge([
            'id'     => null,
            'key'    => null,
            'secret' => null,
            'status' => 'DISABLED',
        ], $consumer));
    }

    // ------------------------------------------------------------------------

    /**
     * Consumer::__toString
     *
     * Generates the basic string serialization of http query string.
     *
     * @return string
     */
    public function __toString()
    {
        return sprintf("oauth_consumer_key=%s&oauth_consumer_secret=%s",
            rawurlencode($this->key),
            rawurlencode($this->secret)
        );
    }
}
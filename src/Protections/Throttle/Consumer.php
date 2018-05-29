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

namespace O2System\Security\Protections\Throttle;

// ------------------------------------------------------------------------

use O2System\Spl\Datastructures\SplArrayObject;

/**
 * Class Consumer
 * @package O2System\Security\Protections\Throttle
 */
class Consumer extends SplArrayObject
{
    public function __construct(array $consumer = [])
    {
        parent::__construct(array_merge([
            'ipAddress' => server_request()->getClientIpAddress(),
            'userAgent' => server_request()->getClientUserAgent(),
            'attempts'  => 0,
        ], $consumer));
    }

    public function getId()
    {
        return md5($this->ipAddress . $this->userAgent);
    }
}
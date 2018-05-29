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

use O2System\Kernel\Http\Message\Request;
use O2System\Security\Protections\Throttle\Consumer;
use O2System\Security\Protections\Throttle\Rate;

/**
 * Class Throttle
 * @package O2System\Security\Protections
 */
class Throttle
{
    protected $key;
    protected $repository;
    protected $rate;
    protected $consumer;

    public function __construct()
    {
        $this->repository = new Throttle\Repository();
    }

    public function setKey($key)
    {
        $this->key = $key;
    }

    public function getConsumerData($consumerId)
    {
        if (class_exists('\O2System\Framework', false)) {
            return cache()->get('throttle-' . $consumerId);
        }
    }

    public function rate(array $config = [])
    {
        $this->rate = new Rate($config);
    }

    public function request(Request $request)
    {
        $this->consumer = new Consumer([
            'ipAddress' => $request->getClientIpAddress(),
            'userAgent' => $request->getClientUserAgent(),
        ]);

        $consumerId = empty($this->key) ? '' : $this->key . '.';
        $consumerId .= $this->consumer->getId();

        if ($this->repository->has($consumerId)) {
            $consumerData = $this->repository->get($consumerId);
            $consumerData[ 'id' ] = $consumerId;
            $consumerData[ 'currentCallTime' ] = $request->getTime();
            $consumerData[ 'attempts' ] = 1;

            $this->consumer->merge($consumerData);
        } else {
            $consumerData = $this->consumer->getArrayCopy();
            $consumerData[ 'id' ] = $consumerId;
            $consumerData[ 'lastCallTime' ] = $consumerData[ 'currentCallTime' ] = $request->getTime();
            $consumerData[ 'attempts' ] = $consumerData[ 'attempts' ] + 1;

            $this->repository->store($consumerId, $consumerData);
        }
    }

    public function verify()
    {
        $currentTime = strtotime(date('r'));
        $timeCall = abs($this->consumer[ 'lastCallTime' ] - $currentTime);

        $this->consumer[ 'lastCallTime' ] = $currentTime;

        if ($timeCall > $this->rate[ 'span' ]) {
            return false;
        } elseif ($this->consumer[ 'attempts' ] > $this->rate[ 'attempts' ]) {
            return false;
        }

        return true;
    }
}
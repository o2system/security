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

use O2System\Spl\Traits\Collectors\ConfigCollectorTrait;

/**
 * Class Rate
 * @package O2System\Security\Protections\Throttle
 */
class Rate
{
    use ConfigCollectorTrait;

    // ------------------------------------------------------------------------

    /**
     * Rate::__construct
     *
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $config = array_merge([
            'span'     => 1,
            'retry'    => 10,
            'attempts' => 5,
        ], $config);

        $this->setConfig($config);
    }
}
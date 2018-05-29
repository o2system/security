<?php
/**
 * This file is part of the O2System PHP Framework package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author         Mohamad Rafi Randoni
 * @copyright      Copyright (c) Steeve Andrian Salim
 */

// ------------------------------------------------------------------------

namespace O2System\Security\Generators;

// ------------------------------------------------------------------------

/**
 * Class Uid
 * @package O2System\Security\Generators
 */
class Uid
{
    public static function generate($length = 8)
    {
        $ids = str_split(time() . mt_rand());
        shuffle($ids);

        $ids = array_slice($ids, 0, $length);

        return implode('', $ids);
    }
}
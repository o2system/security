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
 * Class Uuid
 *
 * UUID (Universally Unique Identifier) Generator.
 * A UUID is a 16-octet (128-bit) number.
 * In its canonical form, a UUID is represented by 32 hexadecimal digits, displayed in five groups separated by hyphens,
 * in the form 8-4-4-4-12 for a total of 36 characters (32 alphanumeric characters and four hyphens).
 *
 * @package O2System\Security\Generators
 */
class Uuid
{
    /**
     * Uuid::generate
     *
     * @return string
     */
    public static function generate()
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0C2f) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0x2Aff), mt_rand(0, 0xffD3), mt_rand(0, 0xff4B)
        );
    }
}
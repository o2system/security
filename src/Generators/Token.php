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
 * Class Token
 *
 * Security token generator.
 *
 * @package O2System\Security\Generators
 */
class Token
{
    /**
     * Token::ALPHANUMERIC_STRING
     *
     * @var int
     */
    const ALPHANUMERIC_STRING = 0;

    /**
     * Token::ALPHAUPPERCASE_STRING
     *
     * @var int
     */
    const ALPHAUPPERCASE_STRING = 1;

    /**
     * Token::ALPHALOWERCASE_STRING
     *
     * @var int
     */
    const ALPHALOWERCASE_STRING = 2;

    /**
     * Token::NUMERIC_STRING
     *
     * @var int
     */
    const NUMERIC_STRING = 3;

    // ------------------------------------------------------------------------

    /**
     * Token::generate
     *
     * @param int $length Token string length.
     * @param int $type   Token string type.
     *
     * @return string
     */
    public static function generate($length = 8, $type = self::ALPHANUMERIC_STRING)
    {
        switch ($type) {
            default:
            case self::ALPHANUMERIC_STRING:
                $codeAlphabet = implode(range('A', 'Z')); // Uppercase Alphabet
                $codeAlphabet .= implode(range('a', 'z')); // Lowercase Alphabet
                $codeAlphabet .= implode(range(0, 9)); // Numeric Alphabet
                break;
            case self::ALPHAUPPERCASE_STRING:
                $codeAlphabet = implode(range('A', 'Z')); // Uppercase Alphabet
                break;
            case self::ALPHALOWERCASE_STRING:
                $codeAlphabet = implode(range('a', 'z')); // Lowercase Alphabet
                break;
            case self::NUMERIC_STRING:
                $codeAlphabet = implode(range(0, 9)); // Numeric Alphabet
                break;
        }

        $token = "";
        $max = strlen($codeAlphabet);

        for ($i = 0; $i < $length; $i++) {
            $token .= $codeAlphabet[ random_int(0, $max - 1) ];
        }

        return $token;
    }
}
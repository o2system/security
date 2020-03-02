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

namespace O2System\Security\Encryptions;

// ------------------------------------------------------------------------

/**
 * Class Hexadecimal
 * @package O2System\Security\Encryptions
 */
class Hexadecimal
{
    /**
     * Binary::$crypt
     *
     * Crypt instance.
     *
     * @var Crypt
     */
    private $crypt;

    // ------------------------------------------------------------------------

    /**
     * Binary::__construct
     */
    public function __construct()
    {
        $this->crypt = new Crypt();
    }

    // ------------------------------------------------------------------------

    /**
     * Hexadecimal::encrypt
     *
     * Encrypt string into numbers.
     *
     * @param string $string String to be encrypted.
     *
     * @return string
     */
    public function encrypt($string)
    {
        $dec = [];
        $hex = str_split($this->crypt->encrypt($string), 4);
        
        foreach ($hex as $char) {
            $dec[] = str_pad(hexdec($char), 5, '0', STR_PAD_LEFT);
        }
        
        return implode('', $dec);
    }

    // ------------------------------------------------------------------------

    /**
     * Hexadecimal::decrypt
     *
     * Decrypt numbers.
     *
     * @param string $string String to be decrypted.
     *
     * @return string
     */
    public function decrypt($string)
    {
        $hex = [];
        $dec = str_split($string, 5);

        foreach ($dec as $char) {
            $hex[] = str_pad(dechex($char), 4, '0', STR_PAD_LEFT);
        }

        return implode('', $hex);
    }

    // ------------------------------------------------------------------------

    /**
     * Hexadecimal::setKey
     *
     * Sets numeric encryption protection key.
     *
     * @param string $key Custom encryption key.
     *
     * @return static
     */
    public function setKey($key)
    {
        $this->crypt->setKey($key);

        return $this;
    }
}
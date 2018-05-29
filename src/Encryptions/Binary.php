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

namespace O2System\Security\Encryptions;

// ------------------------------------------------------------------------

/**
 * Class Binary
 *
 * @package O2System\Security\Encryptions
 */
class Binary
{
    /**
     * Binary::$charactersMap
     *
     * @var array
     */
    private static $charactersMap = [];
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

        /**
         * Special character
         */
        $specialCharacters = [
            "\n",
            "\r",
            "\t",
            '~',
            '`',
            '!',
            '@',
            '#',
            '$',
            '%',
            '^',
            '&',
            '*',
            '(',
            ')',
            '-',
            '_',
            '=',
            '+',
            '{',
            '}',
            '[',
            ']',
            ':',
            ';',
            '"',
            "'",
            '<',
            '>',
            '/',
            '?',
            '\\',
            '|',
            '.',
            ',',
        ];

        // ------------------------------------------------------------------------

        /**
         * Lowercase letter character
         */
        $lowerLetterCharacter = [
            'a',
            'b',
            'c',
            'd',
            'e',
            'f',
            'g',
            'h',
            'i',
            'j',
            'k',
            'l',
            'm',
            'n',
            'o',
            'p',
            'q',
            'r',
            's',
            't',
            'u',
            'v',
            'w',
            'x',
            'y',
            'z',
        ];

        // ------------------------------------------------------------------------

        /**
         * Uppercase letter character
         */
        $upperLetterCharacter = array_map('strtoupper', $lowerLetterCharacter);

        // ------------------------------------------------------------------------

        /**
         * Binary character
         */
        $numericCharacter = range(0, 9, 1);

        // ------------------------------------------------------------------------

        static::$charactersMap = array_merge(
            $specialCharacters,
            $lowerLetterCharacter,
            $upperLetterCharacter,
            $numericCharacter
        );

        if (class_exists('\O2System\Framework', false)) {
            $key = config()->getItem('security')->offsetGet('encryptionKey');
            $letters = str_split($key);
            $cryptoKey = 0;

            foreach ($letters as $letter) {
                if ($number = array_search($letter, static::$charactersMap)) {
                    $cryptoKey = $cryptoKey + $number;
                }
            }

            $charactersMap = static::$charactersMap;
            static::$charactersMap = [];

            if ($cryptoKey > 0) {
                foreach ($charactersMap as $key => $value) {
                    static::$charactersMap[ $key * $cryptoKey ] = $value;
                }
            }
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Binary::encrypt
     *
     * Encrypt string into numbers.
     *
     * @param string $string String to be encrypted.
     *
     * @return string
     */
    public function encrypt($string)
    {
        $numbers = [];
        $letters = str_split($this->crypt->encrypt($string));

        $i = 0;
        foreach ($letters as $letter) {
            if ($number = array_search($letter, static::$charactersMap)) {
                if ($i == 20) {
                    $number = $number . PHP_EOL;
                    $i = 0;
                }

                $numbers[] = $number;

                $i++;
            }
        }

        return implode(' ', $numbers);
    }

    // ------------------------------------------------------------------------

    /**
     * Binary::decrypt
     *
     * Decrypt numbers.
     *
     * @param string $numbers Numbers to be decrypted.
     *
     * @return string
     */
    public function decrypt($numbers)
    {
        $letters = [];
        $numbers = explode(' ', str_replace(PHP_EOL, '', $numbers));

        foreach ($numbers as $number) {
            if (array_key_exists($number, static::$charactersMap)) {
                $letters[] = static::$charactersMap[ $number ];
            }
        }

        return $this->crypt->decrypt(implode('', $letters));
    }

    // ------------------------------------------------------------------------

    /**
     * Binary::setKey
     *
     * Sets numeric encryption protection key.
     *
     * @param string $key Custom encryption key.
     *
     * @return static
     */
    protected function setKey($key)
    {
        $this->crypt->setKey($key);

        return $this;
    }
}
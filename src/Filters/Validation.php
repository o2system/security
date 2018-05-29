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

namespace O2System\Security\Filters;

// ------------------------------------------------------------------------

/**
 * Class Validation
 *
 * @package O2System\Security\Filters
 */
class Validation
{
    /**
     * Validation::isRequired
     *
     * @param $string
     *
     * @return bool
     */
    public static function isRequired($string = null)
    {
        if (empty($string) OR strlen($string) == 0) {
            return false;
        }

        return true;
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isMatches
     *
     * @param $string
     * @param $match
     *
     * @return bool
     */
    public static function isMatches($string, $match)
    {
        if ($string === $match) {
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isRegexMatch
     *
     * Performs a Regular Expression match test.
     *
     * @param    string
     * @param    string    regex
     *
     * @return    bool
     */
    public static function isRegexMatch($string, $regex)
    {
        return (bool)preg_match($regex, $string);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isFloat
     *
     * @param $string
     *
     * @return mixed
     */
    public static function isFloat($string)
    {
        return filter_var($string, FILTER_VALIDATE_FLOAT);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isMaxLength
     *
     * Max Length
     *
     * @param    string
     * @param    string
     *
     * @return    bool
     */
    public static function isMaxLength($string, $length)
    {
        if ( ! is_numeric($length)) {
            return false;
        }

        return ($length >= mb_strlen($string));
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isExactLength
     *
     * Exact Length
     *
     * @param    string
     * @param    string
     *
     * @return    bool
     */
    public static function isExactLength($string, $length)
    {
        if ( ! is_numeric($length)) {
            return false;
        }

        return (mb_strlen($string) === (int)$length);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isDimension
     *
     * @param        $string
     * @param string $format
     *
     * @return bool
     */
    public static function isDimension($string, $format = 'W x H x L')
    {
        $string = strtolower($string);
        $string = preg_replace('/\s+/', '', $string);
        $x_string = explode('x', $string);

        $format = strtolower($format);
        $format = preg_replace('/\s+/', '', $format);
        $x_format = explode('x', $format);

        if (count($x_string) == count($x_format)) {
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isIpv4
     *
     * @param $string
     *
     * @return mixed
     */
    public static function isIpv4($string)
    {
        return filter_var($string, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isIpv6
     *
     * @param $string
     *
     * @return mixed
     */
    public static function isIpv6($string)
    {
        return filter_var($string, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isUrl
     *
     * @param $string
     *
     * @return bool|mixed
     */
    public static function isUrl($string)
    {
        if (preg_match('/^(?:([^:]*)\:)?\/\/(.+)$/', $string, $matches)) {
            if (empty($matches[ 2 ])) {
                return false;
            } elseif ( ! in_array($matches[ 1 ], ['http', 'https'], true)) {
                return false;
            }

            $string = $matches[ 2 ];
        }

        $string = 'http://' . $string;

        return filter_var($string, FILTER_VALIDATE_URL);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isEmail
     *
     * @param $string
     *
     * @return bool
     */
    public static function isEmail($string)
    {
        if (function_exists('idn_to_ascii') && $strpos = strpos($string, '@')) {
            $string = substr($string, 0, ++$strpos) . idn_to_ascii(substr($string, $strpos));
        }

        return (bool)filter_var($string, FILTER_VALIDATE_EMAIL);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isDomain
     *
     * @param $string
     *
     * @return bool
     */
    public static function isDomain($string)
    {
        return (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $string) //valid chars check
            && preg_match("/^.{1,253}$/", $string) //overall length check
            && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $string)); //length of each label
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isBool
     *
     * @param $string
     *
     * @return bool
     */
    public static function isBool($string)
    {
        return (bool)filter_var($string, FILTER_VALIDATE_BOOLEAN);
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isAlpha
     *
     * @param    string $string
     *
     * @return    bool
     */
    public static function isAlpha($string)
    {
        return (bool)ctype_alpha($string);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isAlphaSpaces
     *
     * @param    string $string
     *
     * @return    bool
     */
    public static function isAlphaSpaces($string)
    {
        return (bool)preg_match('/^[A-Z ]+$/i', $string);
    }

    // --------------------------------------------------------------------

    /**
     * Alpha-numeric
     *
     * @param    string $string
     *
     * @return    bool
     */
    public static function isAlphaNumeric($string)
    {
        return (bool)ctype_alnum((string)$string);
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isAlphaNumericSpaces
     *
     * Alpha-numeric w/ spaces
     *
     * @param    string $string
     *
     * @return    bool
     */
    public static function isAlphaNumericSpaces($string)
    {
        return (bool)preg_match('/^[A-Z0-9 ]+$/i', $string);
    }

    /**
     * Validation::isAlphaDash
     *
     * Alpha-numeric with underscores and dashes
     *
     * @param    string
     *
     * @return    bool
     */
    public static function isAlphaDash($string)
    {
        return (bool)preg_match('/^[a-z0-9-]+$/i', $string);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isAlphaUnderscore
     *
     * Alpha-numeric with underscores and dashes
     *
     * @param    string
     *
     * @return    bool
     */
    public static function isAlphaUnderscore($string)
    {
        return (bool)preg_match('/^[a-z0-9_]+$/i', $string);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isAlphaUnderscoreDash
     *
     * Alpha-numeric with underscores and dashes
     *
     * @param    string
     *
     * @return    bool
     */
    public static function isAlphaUnderscoreDash($string)
    {
        return (bool)preg_match('/^[a-z0-9_-]+$/i', $string);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isNumeric
     *
     * @param    string
     *
     * @return    bool
     */
    public static function isNumeric($str)
    {
        return (bool)preg_match('/^[\-+]?[0-9]*\.?[0-9]+$/', $str);

    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isInteger
     *
     * @param    string
     *
     * @return    bool
     */
    public static function isInteger($str)
    {
        return (bool)preg_match('/^[\-+]?[0-9]+$/', $str);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isDecimal
     *
     * Decimal number
     *
     * @param    string
     *
     * @return    bool
     */
    public static function isDecimal($string)
    {
        return (bool)preg_match('/^[\-+]?[0-9]+\.[0-9]+$/', $string);
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isGreater
     *
     * Greater than
     *
     * @param    string
     * @param    int
     *
     * @return    bool
     */
    public static function isGreater($string, $min)
    {
        return is_numeric($string) ? ($string > $min) : false;
    }

    // ------------------------------------------------------------------------

    /**
     * Validation::isGreaterEqual
     *
     * Equal to or Greater than
     *
     * @param    string
     * @param    int
     *
     * @return    bool
     */
    public static function isGreaterEqual($string, $min)
    {
        return (bool)is_numeric($string) ? ($string >= $min) : false;
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isLess
     *
     * Less than
     *
     * @param    string
     * @param    int
     *
     * @return    bool
     */
    public static function isLess($string, $max)
    {
        return (bool)is_numeric($string) ? ($string < $max) : false;
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isLessEqual
     *
     * Equal to or Less than
     *
     * @param    string
     * @param    int
     *
     * @return    bool
     */
    public static function isLessEqual($string, $max)
    {
        return (bool)is_numeric($string) ? ($string <= $max) : false;
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isListed
     *
     * Value should be within an array of values
     *
     * @param    string
     * @param    string
     *
     * @return    bool
     */
    public static function isListed($string, $list)
    {
        if (is_string($list)) {
            $list = explode(',', $list);
            $list = array_map('trim', $list);
        }

        return (bool)in_array($string, $list, true);
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isNatural
     *
     * Is a Natural number  (0,1,2,3, etc.)
     *
     * @param    string
     *
     * @return    bool
     */
    public static function isNatural($string)
    {
        return (bool)ctype_digit((string)$string);
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isNaturalNoZero
     *
     * Is a Natural number, but not a zero  (1,2,3, etc.)
     *
     * @param    string
     *
     * @return    bool
     */
    public static function isNaturalNoZero($string)
    {
        return (bool)($string != 0 && ctype_digit((string)$string));
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isMd5
     *
     * @param $string
     *
     * @return int
     */
    public static function isMd5($string)
    {
        return preg_match('/^[a-f0-9]{32}$/i', $string);
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isMsisdn
     *
     * @param        $string
     * @param string $leading
     *
     * @return bool
     */
    public static function isMsisdn($string, $leading = '62')
    {
        return (bool)preg_match('/^(' . $leading . '[1-9]{1}[0-9]{1,2})[0-9]{6,8}$/', $string);
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isDate
     *
     * @param        $string
     * @param string $format
     *
     * @return bool
     */
    public static function isDate($string, $format = 'Y-m-d')
    {
        $dateTime = \DateTime::createFromFormat($format, $string);

        return (bool)$dateTime !== false && ! array_sum($dateTime->getLastErrors());
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isPassword
     *
     * @param string $string
     * @param int    $length
     * @param string $format
     *
     * @return bool
     */
    public static function isPassword($string, $length = 8, $format = 'uppercase, lowercase, number, special')
    {
        // Length
        if (self::isMinLength($string, $length) === false) {
            return false;
        }

        $format = strtolower($format);
        $format = explode(',', $format);
        $format = array_map('trim', $format);
        $valid = [];

        foreach ($format as $type) {
            switch ($type) {
                case 'uppercase':
                    if (preg_match_all('/[A-Z]/', $string, $uppercase)) {
                        $valid[ $type ] = count($uppercase[ 0 ]);
                    }
                    break;
                case 'lowercase':
                    if (preg_match_all('/[a-z]/', $string, $lowercase)) {
                        $valid[ $type ] = count($lowercase[ 0 ]);
                    }
                    break;
                case 'number':
                case 'numbers':
                    if (preg_match_all('/[0-9]/', $string, $numbers)) {
                        $valid[ $type ] = count($numbers[ 0 ]);
                    }
                    break;
                case 'special character':
                case 'special-character':
                case 'special':
                    // Special Characters
                    if (preg_match_all('/[!@#$%^&*()\-_=+{};:,<.>]/', $string, $special)) {
                        $valid[ $type ] = count($special[ 0 ]);
                    }
                    break;
            }
        }

        $diff = array_diff($format, array_keys($valid));

        return empty($diff) ? true : false;
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isMinLength
     *
     * Minimum Length
     *
     * @param    string
     * @param    string
     *
     * @return    bool
     */
    public static function isMinLength($string, $length)
    {
        if (isset($string)) {
            if ( ! is_numeric($length) or $length == 0) {
                return false;
            }

            return ($length <= mb_strlen($string));
        }

        return false;
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isAscii
     *
     * Chceks if a string is an v4 or v6 ip address.
     *
     * @param   string $string String to check
     * @param   string $which  ipv4 | ipv6
     *
     * @return  bool
     */
    public static function isValidIp($string, $which = null)
    {
        switch (strtolower($which)) {
            case 'ipv4':
                $which = FILTER_FLAG_IPV4;
                break;
            case 'ipv6':
                $which = FILTER_FLAG_IPV6;
                break;
            default:
                $which = null;
                break;
        }

        return (bool)filter_var($string, FILTER_VALIDATE_IP, $which);
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isAscii
     *
     * Tests if a string is standard 7-bit ASCII or not.
     *
     * @param   string $string String to check
     *
     * @return  bool
     */
    public static function isAscii($string)
    {
        return (bool)(preg_match('/[^\x00-\x7F]/S', $string) === 0);
    }

    // --------------------------------------------------------------------

    /**
     * Validation::isBase64
     *
     * Tests a string for characters outside of the Base64 alphabet
     * as defined by RFC 2045 http://www.faqs.org/rfcs/rfc2045
     *
     * @param    string
     *
     * @return    bool
     */
    public function isBase64($string)
    {
        return (bool)(base64_encode(base64_decode($string)) === $string);
    }
}
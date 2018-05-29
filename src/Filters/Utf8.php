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

/*
 * ------------------------------------------------------
 * Important charset-related stuff
 * ------------------------------------------------------
 *
 * Configure mbstring and/or iconv if they are enabled
 * and set MB_ENABLED and ICONV_ENABLED constants, so
 * that we don't repeatedly do extension_loaded() or
 * function_exists() calls.
 *
 * Note: UTF-8 class depends on this. It used to be done
 * in it's constructor, but it's _not_ class-specific.
 *
 */
$charset = strtoupper(o2system()->config[ 'charset' ]);
ini_set('default_charset', $charset);

if (extension_loaded('mbstring')) {
    define('MB_ENABLED', true);

    // mbstring.internal_encoding is deprecated starting with PHP 5.6
    // and it's usage triggers E_DEPRECATED messages.
    if (is_php('5.6', '<=')) {
        @ini_set('mbstring.internal_encoding', $charset);
    }

    // This is required for mb_convert_encoding() to strip invalid characters.
    // That's utilized by UTF8 Class, but it's also done for consistency with iconv.
    mb_substitute_character('none');
} else {
    define('MB_ENABLED', false);
}

// There's an ICONV_IMPL constant, but the PHP manual says that using
// iconv's predefined constants is "strongly discouraged".
if (extension_loaded('iconv')) {
    define('ICONV_ENABLED', true);

    // iconv.internal_encoding is deprecated starting with PHP 5.6
    // and it's usage triggers E_DEPRECATED messages.

    if (is_php('5.6', '<=')) {
        @ini_set('iconv.internal_encoding', $charset);
    }
} else {
    define('ICONV_ENABLED', false);
}

if (is_php('5.6')) {
    ini_set('php.internal_encoding', $charset);
}


class Utf8
{
    protected $isEnabled = false;

    /**
     * Class constructor
     *
     * Determines if UTF-8 support is to be enabled.
     *
     * @access  public
     */
    public function __construct()
    {
        if (
            defined('PREG_BAD_UTF8_ERROR')                // PCRE must support UTF-8
            AND (ICONV_ENABLED === true || MB_ENABLED === true)    // iconv or mbstring must be installed
            AND strtoupper(o2system()->config[ 'charset' ]) === 'UTF-8'    // Application charset must be UTF-8
        ) {
            $this->isEnabled = true;
            logger()->debug('LOG_DEBUG_UTF8_SUPPORT_ENABLED');
        } else {
            $this->isEnabled = false;
            logger()->debug('LOG_DEBUG_UTF8_SUPPORT_DISABLED');
        }

        logger()->debug('LOG_DEBUG_CLASS_INITIALIZED', [__CLASS__]);
    }

    // --------------------------------------------------------------------

    public function isEnabled()
    {
        return (bool)$this->isEnabled;
    }

    /**
     * Clean UTF-8 strings
     *
     * Ensures strings contain only valid UTF-8 characters.
     *
     * @param    string $string String to clean
     *
     * @return    string
     */
    public function cleanString($string)
    {
        if ($this->isAscii($string) === false) {
            if (MB_ENABLED) {
                $string = mb_convert_encoding($string, 'UTF-8', 'UTF-8');
            } elseif (ICONV_ENABLED) {
                $string = @iconv('UTF-8', 'UTF-8//IGNORE', $string);
            }
        }

        return $string;
    }

    // --------------------------------------------------------------------

    /**
     * Is ASCII?
     *
     * Tests if a string is standard 7-bit ASCII or not.
     *
     * @param    string $string String to check
     *
     * @return    bool
     */
    public function isAscii($string)
    {
        return (preg_match('/[^\x00-\x7F]/S', $string) === 0);
    }

    // --------------------------------------------------------------------

    /**
     * Remove ASCII control characters
     *
     * Removes all ASCII control characters except horizontal tabs,
     * line feeds, and carriage returns, as all others can cause
     * problems in XML.
     *
     * @param    string $string String to clean
     *
     * @return    string
     */
    public function safeAsciiForXML($string)
    {
        return remove_invisible_characters($string, false);
    }

    // --------------------------------------------------------------------

    /**
     * Convert to UTF-8
     *
     * Attempts to convert a string to UTF-8.
     *
     * @param    string $string   Input string
     * @param    string $encoding Input encoding
     *
     * @return    string    $str encoded in UTF-8 or FALSE on failure
     */
    public function convertString($string, $encoding)
    {
        if (MB_ENABLED) {
            return mb_convert_encoding($string, 'UTF-8', $encoding);
        } elseif (ICONV_ENABLED) {
            return @iconv($encoding, 'UTF-8', $string);
        }

        return false;
    }
}
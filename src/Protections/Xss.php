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

/**
 * Class Xss
 *
 * @package O2System\Security\Protections
 */
class Xss
{
    /**
     * Xss::$token
     *
     * Active XSS protection token.
     *
     * @var string
     */
    private $token;

    // ------------------------------------------------------------------------

    /**
     * Xss::__construct
     */
    public function __construct()
    {
        $this->config = require(str_replace('Protections', 'Config', __DIR__) . DIRECTORY_SEPARATOR . 'Xss.php');

        if (false === ($this->token = $this->getToken())) {
            $this->regenerate();
        }
    }

    // --------------------------------------------------------------------------------------

    /**
     * Xss::getToken
     *
     * Gets session XSS protection token.
     *
     * @return string|bool Returns FALSE if XSS protection token is not set.
     */
    public function getToken()
    {
        if (isset($_SESSION[ 'xssToken' ])) {
            return $_SESSION[ 'xssToken' ];
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Xss::regenerate
     *
     * Regenerate XSS protection token.
     *
     * @return void
     */
    public function regenerate()
    {
        $_SESSION[ 'xssToken' ] = $this->token = md5(uniqid(mt_rand(), true) . 'XSS');
    }

    // ------------------------------------------------------------------------

    /**
     * Csrf::verify
     *
     * Checks if the posted XSS protection token is valid.
     *
     * @param string $token
     *
     * @return bool
     */
    public function verify($token = null)
    {
        $token = isset($token)
            ? $token
            : input()->postGet('xssToken');

        if (false !== ($this->getToken() === $token)) {
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Clean
     *
     * @param  string  $string
     * @param  boolean $is_image
     *
     * @return string
     */
    public function clean($string, $is_image = false)
    {
        // Is the string an array?
        if (is_array($string)) {
            while (list($key) = each($string)) {
                $string[ $key ] = $this->clean($string[ $key ]);
            }

            return $string;
        }

        // Remove Invisible Characters
        $string = remove_invisible_characters($string);

        /*
         * URL Decode
         *
         * Just in case stuff like this is submitted:
         *
         * <a href="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">Google</a>
         *
         * Note: Use rawurldecode() so it does not remove plus signs
         */
        do {
            $string = rawurldecode($string);
        } while (preg_match('/%[0-9a-f]{2,}/i', $string));

        /*
         * Convert character entities to ASCII
         *
         * This permits our tests below to work reliably.
         * We only convert entities that are within tags since
         * these are the ones that will pose security problems.
         */
        $string = preg_replace_callback(
            "/[^a-z0-9>]+[a-z0-9]+=([\'\"]).*?\\1/si",
            [$this, 'convertAttribute'],
            $string
        );

        $string = preg_replace_callback('/<\w+.*/si', [$this, 'decodeEntity'], $string);

        // Remove Invisible Characters Again!
        $string = remove_invisible_characters($string);

        /*
         * Convert all tabs to spaces
         *
         * This prevents strings like this: ja  vascript
         * NOTE: we deal with spaces between characters later.
         * NOTE: preg_replace was found to be amazingly slow here on
         * large blocks of data, so we use str_replace.
         */
        $string = str_replace("\t", ' ', $string);

        // Capture converted string for later comparison
        $converted_string = $string;

        // Remove Strings that are never allowed
        $string = $this->doNeverAllowed($string);

        /*
         * Makes PHP tags safe
         *
         * Note: XML tags are inadvertently replaced too:
         *
         * <?xml
         *
         * But it doesn't seem to pose a problem.
         */
        if ($is_image === true) {
            // Images have a tendency to have the PHP short opening and
            // closing tags every so often so we skip those and only
            // do the long opening tags.
            $string = preg_replace('/<\?(php)/i', '&lt;?\\1', $string);
        } else {
            $string = str_replace(['<?', '?' . '>'], ['&lt;?', '?&gt;'], $string);
        }

        /*
         * Compact any exploded words
         *
         * This corrects words like:  j a v a s c r i p t
         * These words are compacted back to their correct state.
         */
        $words = [
            'javascript',
            'expression',
            'vbscript',
            'jscript',
            'wscript',
            'vbs',
            'script',
            'base64',
            'applet',
            'alert',
            'document',
            'write',
            'cookie',
            'window',
            'confirm',
            'prompt',
            'eval',
        ];

        foreach ($words as $word) {
            $word = implode('\s*', str_split($word)) . '\s*';

            // We only want to do this when it is followed by a non-word character
            // That way valid stuff like "dealer to" does not become "dealerto"
            $string = preg_replace_callback(
                '#(' . substr($word, 0, -3) . ')(\W)#is',
                [$this, 'compactExplodedWords'],
                $string
            );
        }

        /*
         * Remove disallowed Javascript in links or img tags
         * We used to do some version comparisons and use of stripos(),
         * but it is dog slow compared to these simplified non-capturing
         * preg_match(), especially if the pattern exists in the string
         *
         * Note: It was reported that not only space characters, but all in
         * the following pattern can be parsed as separators between a tag name
         * and its attributes: [\d\s"\'`;,\/\=\(\x00\x0B\x09\x0C]
         * ... however, remove_invisible_characters() above already strips the
         * hex-encoded ones, so we'll skip them below.
         */
        do {
            $original = $string;
            if (preg_match('/<a/i', $string)) {
                $string = preg_replace_callback(
                    '#<a[^a-z0-9>]+([^>]*?)(?:>|$)#si',
                    [$this, 'jsLinkRemoval'],
                    $string
                );
            }
            if (preg_match('/<img/i', $string)) {
                $string = preg_replace_callback(
                    '#<img[^a-z0-9]+([^>]*?)(?:\s?/?>|$)#si',
                    [$this, 'jsImgRemoval'],
                    $string
                );
            }
            if (preg_match('/script|xss/i', $string)) {
                $string = preg_replace('#</*(?:script|xss).*?>#si', '[removed]', $string);
            }
        } while ($original !== $string);
        unset($original);

        /*
         * Sanitize naughty HTML elements
         *
         * If a tag containing any of the words in the list
         * below is found, the tag gets converted to entities.
         *
         * So this: <blink>
         * Becomes: &lt;blink&gt;
         */
        $pattern = '#'
            . '<((?<slash>/*\s*)(?<tagName>[a-z0-9]+)(?=[^a-z0-9]|$)'
            // tag start and name, followed by a non-tag character
            . '[^\s\042\047a-z0-9>/=]*'
            // a valid attribute character immediately after the tag would count as a separator
            // optional attributes
            . '(?<attributes>(?:[\s\042\047/=]*'
            // non-attribute characters, excluding > (tag close) for obvious reasons
            . '[^\s\042\047>/=]+'
            // attribute characters
            // optional attribute-value
            . '(?:\s*='
            // attribute-value separator
            . '(?:[^\s\042\047=><`]+|\s*\042[^\042]*\042|\s*\047[^\047]*\047|\s*(?U:[^\s\042\047=><`]*))'
            // single, double or non-quoted value
            . ')?'
            // end optional attribute-value group
            . ')*)'
            // end optional attributes group
            . '[^>]*)(?<closeTag>\>)?#isS';
        // Note: It would be nice to optimize this for speed, BUT
        //       only matching the naughty elements here results in
        //       false positives and in turn - vulnerabilities!
        do {
            $old_string = $string;
            $string = preg_replace_callback($pattern, [$this, 'sanitizeNaughtyHTML'], $string);
        } while ($old_string !== $string);

        unset($old_string);

        /*
         * Sanitize naughty scripting elements
         *
         * Similar to above, only instead of looking for
         * tags it looks for PHP and JavaScript commands
         * that are disallowed. Rather than removing the
         * code, it simply converts the parenthesis to entities
         * rendering the code un-executable.
         *
         * For example: eval('some code')
         * Becomes: eval&#40;'some code'&#41;
         */
        $string = preg_replace(
            '#(alert|prompt|confirm|cmd|passthru|eval|exec|expression|system|fopen|fsockopen|file|file_get_contents|readfile|unlink)(\s*)\((.*?)\)#si',
            '\\1\\2&#40;\\3&#41;',
            $string
        );

        // Final clean up
        // This adds a bit of extra precaution in case
        // something got through the above filters
        $string = $this->doNeverAllowed($string);

        /*
         * Images are Handled in a Special Way
         * - Essentially, we want to know that after all of the character
         * conversion is done whether any unwanted, likely XSS, code was found.
         * If not, we return TRUE, as the image is clean.
         * However, if the string post-conversion does not matched the
         * string post-removal of XSS, then it fails, as there was unwanted XSS
         * code found and removed/changed during processing.
         */
        if ($is_image === true) {
            return ($string === $converted_string);
        }

        return $string;
    }

    // --------------------------------------------------------------------------------------

    /**
     * Do Never Allowed
     *
     * @used-by    XSS::clean()
     *
     * @param    string
     *
     * @return    string
     */
    protected function doNeverAllowed($string)
    {
        $string = str_replace(
            array_keys($this->config[ 'never_allowed_strings' ]),
            $this->config[ 'never_allowed_strings' ],
            $string
        );

        foreach ($this->config[ 'never_allowed_regex' ] as $regex) {
            $string = preg_replace('#' . $regex . '#is', '[removed]', $string);
        }

        return $string;
    }

    // --------------------------------------------------------------------

    /**
     * Compact Exploded Words
     *
     * Callback method for xss_clean() to remove whitespace from
     * things like 'j a v a s c r i p t'.
     *
     * @used-by    XSS::clean()
     *
     * @param    array $matches
     *
     * @return    string
     */
    protected function compactExplodedWords($matches)
    {
        return preg_replace('/\s+/s', '', $matches[ 1 ]) . $matches[ 2 ];
    }

    // --------------------------------------------------------------------

    /**
     * Sanitize Naughty HTML
     *
     * Callback method for xss_clean() to remove naughty HTML elements.
     *
     * @used-by    XSS::clean()
     *
     * @param    array $matches
     *
     * @return    string
     */
    protected function sanitizeNaughtyHTML($matches)
    {
        // First, escape unclosed tags
        if (empty($matches[ 'closeTag' ])) {
            return '&lt;' . $matches[ 1 ];
        } // Is the element that we caught naughty? If so, escape it
        elseif (in_array(strtolower($matches[ 'tagName' ]), $this->config[ 'naughty_tags' ], true)) {
            return '&lt;' . $matches[ 1 ] . '&gt;';
        } // For other tags, see if their attributes are "evil" and strip those
        elseif (isset($matches[ 'attributes' ])) {
            // We'll store the already fitlered attributes here
            $attributes = [];

            // Attribute-catching pattern
            $attributes_pattern = '#'
                . '(?<name>[^\s\042\047>/=]+)'
                // attribute characters
                // optional attribute-value
                . '(?:\s*=(?<value>[^\s\042\047=><`]+|\s*\042[^\042]*\042|\s*\047[^\047]*\047|\s*(?U:[^\s\042\047=><`]*)))'
                // attribute-value separator
                . '#i';

            // Blacklist pattern for evil attribute names
            $is_evil_pattern = '#^(' . implode('|', $this->config[ 'evil_attributes' ]) . ')$#i';

            // Each iteration filters a single attribute
            do {
                // Strip any non-alpha characters that may preceed an attribute.
                // Browsers often parse these incorrectly and that has been a
                // of numerous XSS issues we've had.
                $matches[ 'attributes' ] = preg_replace('#^[^a-z]+#i', '', $matches[ 'attributes' ]);

                if ( ! preg_match($attributes_pattern, $matches[ 'attributes' ], $attribute, PREG_OFFSET_CAPTURE)) {
                    // No (valid) attribute found? Discard everything else inside the tag
                    break;
                }

                if (
                    // Is it indeed an "evil" attribute?
                    preg_match($is_evil_pattern, $attribute[ 'name' ][ 0 ])
                    // Or does it have an equals sign, but no value and not quoted? Strip that too!
                    OR (trim($attribute[ 'value' ][ 0 ]) === '')
                ) {
                    $attributes[] = 'xss=removed';
                } else {
                    $attributes[] = $attribute[ 0 ][ 0 ];
                }

                $matches[ 'attributes' ] = substr(
                    $matches[ 'attributes' ],
                    $attribute[ 0 ][ 1 ] + strlen($attribute[ 0 ][ 0 ])
                );
            } while ($matches[ 'attributes' ] !== '');
            $attributes = empty($attributes)
                ? ''
                : ' ' . implode(' ', $attributes);

            return '<' . $matches[ 'slash' ] . $matches[ 'tagName' ] . $attributes . '>';
        }

        return $matches[ 0 ];
    }

    // --------------------------------------------------------------------

    /**
     * JS Link Removal
     *
     * Callback method for xss_clean() to sanitize links.
     *
     * This limits the PCRE backtracks, making it more performance friendly
     * and prevents PREG_BACKTRACK_LIMIT_ERROR from being triggered in
     * PHP 5.2+ on link-heavy strings.
     *
     * @used-by    XSS::clean()
     *
     * @param    array $match
     *
     * @return    string
     */
    protected function jsLinkRemoval($match)
    {
        return str_replace(
            $match[ 1 ],
            preg_replace(
                '#href=.*?(?:(?:alert|prompt|confirm)(?:\(|&\#40;)|javascript:|livescript:|mocha:|charset=|window\.|document\.|\.cookie|<script|<xss|data\s*:)#si',
                '',
                $this->filterAttributes(str_replace(['<', '>'], '', $match[ 1 ]))
            ),
            $match[ 0 ]
        );
    }

    // --------------------------------------------------------------------

    /**
     * Filter Attributes
     *
     * Filters tag attributes for consistency and safety.
     *
     * @used-by    Security::jsImgRemoval()
     * @used-by    Security::jsLinkRemoval()
     *
     * @param    string $str
     *
     * @return    string
     */
    protected function filterAttributes($str)
    {
        $out = '';
        if (preg_match_all('#\s*[a-z\-]+\s*=\s*(\042|\047)([^\\1]*?)\\1#is', $str, $matches)) {
            foreach ($matches[ 0 ] as $match) {
                $out .= preg_replace('#/\*.*?\*/#s', '', $match);
            }
        }

        return $out;
    }

    // --------------------------------------------------------------------

    /**
     * JS Image Removal
     *
     * Callback method for xss_clean() to sanitize image tags.
     *
     * This limits the PCRE backtracks, making it more performance friendly
     * and prevents PREG_BACKTRACK_LIMIT_ERROR from being triggered in
     * PHP 5.2+ on image tag heavy strings.
     *
     * @used-by    XSS::clean()
     *
     * @param    array $match
     *
     * @return    string
     */
    protected function jsImgRemoval($match)
    {
        return str_replace(
            $match[ 1 ],
            preg_replace(
                '#src=.*?(?:(?:alert|prompt|confirm)(?:\(|&\#40;)|javascript:|livescript:|mocha:|charset=|window\.|document\.|\.cookie|<script|<xss|base64\s*,)#si',
                '',
                $this->filterAttributes(str_replace(['<', '>'], '', $match[ 1 ]))
            ),
            $match[ 0 ]
        );
    }

    // --------------------------------------------------------------------

    /**
     * Attribute Conversion
     *
     * @used-by    XSS::clean()
     *
     * @param    array $match
     *
     * @return    string
     */
    protected function convertAttribute($match)
    {
        return str_replace(['>', '<', '\\'], ['&gt;', '&lt;', '\\\\'], $match[ 0 ]);
    }

    // ------------------------------------------------------------------------

    /**
     * HTML Entity Decode Callback
     *
     * @used-by    XSS::clean()
     *
     * @param    array $match
     *
     * @return    string
     */
    protected function decodeEntity($match)
    {
        // Protect GET variables in URLs
        // 901119URL5918AMP18930PROTECT8198
        $match = preg_replace('|\&([a-z\_0-9\-]+)\=([a-z\_0-9\-/]+)|i', $this->token . '\\1=\\2', $match[ 0 ]);

        // Decode, then un-protect URL GET vars
        return str_replace(
            $this->token,
            '&',
            $this->entityDecode($match, config()->getItem('charset'))
        );
    }

    // --------------------------------------------------------------------

    /**
     * HTML Entities Decode
     *
     * A replacement for html_entity_decode()
     *
     * The reason we are not using html_entity_decode() by itself is because
     * while it is not technically correct to leave out the semicolon
     * at the end of an entity most browsers will still interpret the entity
     * correctly. html_entity_decode() does not convert entities without
     * semicolons, so we are left with our own little solution here. Bummer.
     *
     * @link    http://php.net/html-entity-decode
     *
     * @param    string $string  Input
     * @param    string $charset Character set
     *
     * @return    string
     */
    protected function entityDecode($string, $charset = null)
    {
        if (strpos($string, '&') === false) {
            return $string;
        }

        static $_entities;

        isset($charset) || $charset = config()->getItem('charset');
        $flag = ENT_COMPAT | ENT_HTML5;

        do {
            $str_compare = $string;

            // Decode standard entities, avoiding false positives
            if ($c = preg_match_all('/&[a-z]{2,}(?![a-z;])/i', $string, $matches)) {
                if ( ! isset($_entities)) {
                    $_entities = array_map(
                        'strtolower',
                        get_html_translation_table(HTML_ENTITIES, $flag)
                    );
                }

                $replace = [];
                $matches = array_unique(array_map('strtolower', $matches[ 0 ]));
                for ($i = 0; $i < $c; $i++) {
                    if (($char = array_search($matches[ $i ] . ';', $_entities, true)) !== false) {
                        $replace[ $matches[ $i ] ] = $char;
                    }
                }

                $string = str_ireplace(array_keys($replace), array_values($replace), $string);
            }

            // Decode numeric & UTF16 two byte entities
            $string = html_entity_decode(
                preg_replace('/(&#(?:x0*[0-9a-f]{2,5}(?![0-9a-f;])|(?:0*\d{2,4}(?![0-9;]))))/iS', '$1;', $string),
                $flag,
                $charset
            );
        } while ($str_compare !== $string);

        return $string;
    }

}
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

return [
    /**
     * List of never allowed strings
     *
     * @var    array
     */
    'never_allowed_strings'  => [
        'document.cookie' => '[removed]',
        'document.write'  => '[removed]',
        '.parentNode'     => '[removed]',
        '.innerHTML'      => '[removed]',
        '-moz-binding'    => '[removed]',
        '<!--'            => '&lt;!--',
        '-->'             => '--&gt;',
        '<![CDATA['       => '&lt;![CDATA[',
        '<comment>'       => '&lt;comment&gt;',
    ],

    /**
     * List of never allowed regex replacements
     *
     * @var    array
     */
    'never_allowed_regex'    => [
        'javascript\s*:',
        '(document|(document\.)?window)\.(location|on\w*)',
        'expression\s*(\(|&\#40;)', // CSS and IE
        'vbscript\s*:', // IE, surprise!
        'wscript\s*:', // IE
        'jscript\s*:', // IE
        'vbs\s*:', // IE
        'Redirect\s+30\d',
        "([\"'])?data\s*:[^\\1]*?base64[^\\1]*?,[^\\1]*?\\1?",
    ],

    /**
     * List of naughty html tags
     *
     * @var    array
     */
    'naughty_tags'           => [
        'alert',
        'prompt',
        'confirm',
        'applet',
        'audio',
        'basefont',
        'base',
        'behavior',
        'bgsound',
        'blink',
        'body',
        'embed',
        'expression',
        'form',
        'frameset',
        'frame',
        'head',
        'html',
        'ilayer',
        'iframe',
        'input',
        'button',
        'select',
        'isindex',
        'layer',
        'link',
        'meta',
        'keygen',
        'object',
        'plaintext',
        'style',
        'script',
        'textarea',
        'title',
        'math',
        'video',
        'svg',
        'xml',
        'xss',
    ],

    /**
     * List of evil html tags attributes
     *
     * @var    array
     */
    'evil_attributes'        => [
        'on\w+',
        'style',
        'xmlns',
        'formaction',
        'form',
        'xlink:href',
        'FSCommand',
        'seekSegmentTime',
    ],

    /**
     * List of sql commands
     *
     * @var    array
     */
    'sql_injection_commands' => [
        'union',
        'sql',
        'mysql',
        'database',
        'cookie',
        'coockie',
        'select',
        'from',
        'where',
        'benchmark',
        'concat',
        'table',
        'into',
        'by',
        'values',
        'exec',
        'shell',
        'truncate',
        'wget',
        '/**/',
    ],
];
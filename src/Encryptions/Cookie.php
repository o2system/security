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
 * Class Cookie
 *
 * @package O2System\Security\Encryptions
 */
class Cookie
{
    /**
     * Cookie::$crypt
     *
     * Crypt instance.
     *
     * @var Crypt
     */
    private $crypt;

    /**
     * Cookie::$options
     *
     * Cookie set options.
     *
     * @var array
     */
    private $options = [];

    // ------------------------------------------------------------------------

    /**
     * Cookie::__construct
     */
    public function __construct()
    {
        $this->crypt = new Crypt();

        $this->options = [
            'expire'   => 0,
            'path'     => '/',
            'domain'   => null,
            'secure'   => false,
            'httpOnly' => false,
        ];

        if (class_exists('\O2System\Framework', false)) {
            $this->options = config()->getItem('cookie')->getArrayCopy();
            $this->options[ 'expire' ] = time() + $this->options[ 'lifetime' ];
            unset($this->options[ 'lifetime' ]);
        }

        $this->options[ 'domain' ] = empty($this->options[ 'domain' ])
            ? isset($_SERVER[ 'HTTP_HOST' ])
                ? $_SERVER[ 'HTTP_HOST' ]
                : $_SERVER[ 'SERVER_NAME' ]
            : $this->options[ 'domain' ];
    }

    // ------------------------------------------------------------------------

    /**
     * Cookie::setOptions
     *
     * Sets default cookie options.
     *
     * @param array $options Cookie set options.
     *
     * @return static
     */
    public function setOptions(array $options)
    {
        foreach ($options as $key => $value) {
            if (array_key_exists($key, $this->options)) {
                $this->options[ $key ] = $value;
            }
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Cookie::encrypt
     *
     * Encrypt a cookie.
     *
     * @param string $name  Cookie name.
     * @param string $value Cookie value.
     *
     * @return bool
     */
    public function encrypt($name, $value)
    {
        $value = is_array($value) || is_object($value)
            ? serialize($value)
            : $value;

        $name = isset($this->options[ 'prefix' ])
            ? $this->options[ 'prefix' ] . $name
            : $name;

        $value = $this->crypt->encrypt($value);

        return setcookie(
            $name,
            $value,
            $this->options[ 'expire' ],
            $this->options[ 'path' ],
            $this->options[ 'domain' ],
            false,
            false
        );
    }

    // ------------------------------------------------------------------------

    /**
     * Cookie::decrypt
     *
     * Decrypt a cookie.
     *
     * @param string $name Cookie name.
     *
     * @return string|bool Returns FALSE if cookie is not exists or the decryption failure.
     */
    public function decrypt($name)
    {
        $name = isset($this->options[ 'prefix' ])
            ? $this->options[ 'prefix' ] . $name
            : $name;

        if ($value = input()->cookie($name)) {
            return $this->crypt->decrypt($value);
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Cookie::setKey
     *
     * Sets cookie encryption protection key.
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
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

use O2System\Spl\Exceptions\Logic\BadFunctionCall\BadPhpExtensionCallException;
use O2System\Spl\Exceptions\Logic\BadFunctionCallException;

/**
 * Class Crypt
 *
 * Provides two-way keyed encryption via PHP's MCrypt and/or OpenSSL extensions.
 * Based-on CodeIgniter v3.x.x Encryption library class.
 *
 * @author  Andrey Andreev
 *          Steeve Andrian Salim
 * @package O2System\Security\Encryptions
 */
class Crypt
{
    /**
     * mbstring.func_override flag
     *
     * @var    bool
     */
    protected static $isFunctionOverride;
    /**
     * Encryption cipher
     *
     * @var    string
     */
    protected $cipher = 'aes-128';
    /**
     * Cipher mode
     *
     * @var    string
     */
    protected $mode = 'cbc';
    /**
     * Cipher handle
     *
     * @var    mixed
     */
    protected $handle;
    /**
     * Encryption key
     *
     * @var    string
     */
    protected $key;
    /**
     * PHP extension to be used
     *
     * @var    string
     */
    protected $driver;
    /**
     * List of usable drivers (PHP extensions)
     *
     * @var    array
     */
    protected $drivers = [];
    /**
     * List of available modes
     *
     * @var    array
     */
    protected $modes
        = [
            'mcrypt'  => [
                'cbc'    => 'cbc',
                'ecb'    => 'ecb',
                'ofb'    => 'nofb',
                'ofb8'   => 'ofb',
                'cfb'    => 'ncfb',
                'cfb8'   => 'cfb',
                'ctr'    => 'ctr',
                'stream' => 'stream',
            ],
            'openssl' => [
                'cbc'    => 'cbc',
                'ecb'    => 'ecb',
                'ofb'    => 'ofb',
                'cfb'    => 'cfb',
                'cfb8'   => 'cfb8',
                'ctr'    => 'ctr',
                'stream' => '',
                'xts'    => 'xts',
            ],
        ];
    /**
     * List of supported HMAC algorithms
     *
     * name => digest size pairs
     *
     * @var    array
     */
    protected $digests
        = [
            'sha224' => 28,
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
        ];

    // --------------------------------------------------------------------

    /**
     * Crypt::__construct
     *
     * @param array $params
     *
     * @throws \O2System\Spl\Exceptions\Logic\BadFunctionCall\BadPhpExtensionCallException
     */
    public function __construct(array $params = [])
    {
        $this->drivers = [
            'mcrypt'  => defined('MCRYPT_DEV_URANDOM'),
            'openssl' => extension_loaded('openssl'),
        ];

        if ( ! $this->drivers[ 'mcrypt' ] && ! $this->drivers[ 'openssl' ]) {
            //Encryption: Unable to find an available encryption driver.
            throw new BadPhpExtensionCallException('E_SECURITY_CRYPT_UNABLE_TO_FIND_DRIVER');
        }

        isset(self::$isFunctionOverride) OR
        self::$isFunctionOverride = (extension_loaded('mbstring') && ini_get('mbstring.func_override'));
        $this->initialize($params);

        $key = get_called_class();

        if (class_exists('\O2System\Framework', false)) {
            $key = config()->getItem('security')->offsetGet('encryptionKey');
        }

        if ( ! isset($this->key) && self::strlen($key) > 0) {
            $this->key = $key;
        }
    }

    // --------------------------------------------------------------------

    /**
     * Initialize
     *
     * @param    array $params Configuration parameters
     *
     * @return static
     * @throws \O2System\Spl\Exceptions\Logic\BadFunctionCall\BadPhpExtensionCallException
     */
    public function initialize(array $params)
    {
        if ( ! empty($params[ 'driver' ])) {
            if (isset($this->drivers[ $params[ 'driver' ] ])) {
                if ($this->drivers[ $params[ 'driver' ] ]) {
                    $this->driver = $params[ 'driver' ];
                } else {
                    //"Encryption: Driver '" . $params[ 'driver' ] . "' is not available."
                    throw new BadPhpExtensionCallException(
                        'E_SECURITY_CRYPT_DRIVER_NOT_AVAILABLE', $params[ 'driver' ]
                    );
                }
            } else {
                // "Encryption: Unknown driver '" . $params[ 'driver' ] . "' cannot be configured."
                throw new BadPhpExtensionCallException(
                    'E_SECURITY_CRYPT_DRIVER_NOT_CONFIGURED',
                    0,
                    [$params[ 'driver' ]]
                );
            }
        }

        if (empty($this->driver)) {
            $this->driver = ($this->drivers[ 'openssl' ] === true)
                ? 'openssl'
                : 'mcrypt';
        }

        empty($params[ 'cipher' ]) && $params[ 'cipher' ] = $this->cipher;
        empty($params[ 'key' ]) OR $this->key = $params[ 'key' ];
        $this->{$this->driver . 'Initialize'}($params);

        return $this;
    }

    // --------------------------------------------------------------------

    /**
     * Byte-safe strlen()
     *
     * @param    string $str
     *
     * @return    int
     */
    protected static function strlen($str)
    {
        return (self::$isFunctionOverride)
            ? mb_strlen($str, '8bit')
            : strlen($str);
    }

    // --------------------------------------------------------------------

    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }

    // --------------------------------------------------------------------

    /**
     * Encrypt
     *
     * @param    string $data   Input data
     * @param    array  $params Input parameters
     *
     * @return    string
     */
    public function encrypt($data, array $params = null)
    {
        if (($params = $this->getParams($params)) === false) {
            return false;
        }

        isset($params[ 'key' ]) OR
        $params[ 'key' ] = $this->hkdf($this->key, 'sha512', null, self::strlen($this->key), 'encryption');

        if (($data = $this->{$this->driver . 'Encrypt'}($data, $params)) === false) {
            return false;
        }

        $params[ 'base64' ] && $data = base64_encode($data);

        if (isset($params[ 'hmac_digest' ])) {
            isset($params[ 'hmac_key' ]) OR
            $params[ 'hmac_key' ] = $this->hkdf($this->key, 'sha512', null, null, 'authentication');

            return hash_hmac($params[ 'hmac_digest' ], $data, $params[ 'hmac_key' ], ! $params[ 'base64' ]) . $data;
        }

        return $data;
    }

    /**
     * Get params
     *
     * @param    array $params Input parameters
     *
     * @return    array|bool
     */
    protected function getParams($params)
    {
        if (empty($params)) {
            return isset($this->cipher, $this->mode, $this->key, $this->handle)
                ? [
                    'handle'      => $this->handle,
                    'cipher'      => $this->cipher,
                    'mode'        => $this->mode,
                    'key'         => null,
                    'base64'      => true,
                    'hmac_digest' => 'sha512',
                    'hmac_key'    => null,
                ]
                : false;
        } elseif ( ! isset($params[ 'cipher' ], $params[ 'mode' ], $params[ 'key' ])) {
            return false;
        }

        if (isset($params[ 'mode' ])) {
            $params[ 'mode' ] = strtolower($params[ 'mode' ]);
            if ( ! isset($this->modes[ $this->driver ][ $params[ 'mode' ] ])) {
                return false;
            } else {
                $params[ 'mode' ] = $this->modes[ $this->driver ][ $params[ 'mode' ] ];
            }
        }

        if (isset($params[ 'hmac' ]) && $params[ 'hmac' ] === false) {
            $params[ 'hmac_digest' ] = $params[ 'hmac_key' ] = null;
        } else {
            if ( ! isset($params[ 'hmac_key' ])) {
                return false;
            } elseif (isset($params[ 'hmac_digest' ])) {
                $params[ 'hmac_digest' ] = strtolower($params[ 'hmac_digest' ]);
                if ( ! isset($this->digests[ $params[ 'hmac_digest' ] ])) {
                    return false;
                }
            } else {
                $params[ 'hmac_digest' ] = 'sha512';
            }
        }

        $params = [
            'handle'      => null,
            'cipher'      => $params[ 'cipher' ],
            'mode'        => $params[ 'mode' ],
            'key'         => $params[ 'key' ],
            'base64'      => isset($params[ 'raw_data' ])
                ? ! $params[ 'raw_data' ]
                : false,
            'hmac_digest' => $params[ 'hmac_digest' ],
            'hmac_key'    => $params[ 'hmac_key' ],
        ];

        $this->cipherAlias($params[ 'cipher' ]);
        $params[ 'handle' ] = ($params[ 'cipher' ] !== $this->cipher OR $params[ 'mode' ] !== $this->mode)
            ? $this->{$this->driver . 'GetHandle'}($params[ 'cipher' ], $params[ 'mode' ])
            : $this->handle;

        return $params;
    }

    // --------------------------------------------------------------------

    /**
     * Cipher alias
     *
     * Tries to translate cipher names between MCrypt and OpenSSL's "dialects".
     *
     * @param    string $cipher Cipher name
     *
     * @return    void
     */
    protected function cipherAlias(&$cipher)
    {
        static $dictionary;

        if (empty($dictionary)) {
            $dictionary = [
                'mcrypt'  => [
                    'aes-128'   => 'rijndael-128',
                    'aes-192'   => 'rijndael-128',
                    'aes-256'   => 'rijndael-128',
                    'des3-ede3' => 'tripledes',
                    'bf'        => 'blowfish',
                    'cast5'     => 'cast-128',
                    'rc4'       => 'arcfour',
                    'rc4-40'    => 'arcfour',
                ],
                'openssl' => [
                    'rijndael-128' => 'aes-128',
                    'tripledes'    => 'des-ede3',
                    'blowfish'     => 'bf',
                    'cast-128'     => 'cast5',
                    'arcfour'      => 'rc4-40',
                    'rc4'          => 'rc4-40',
                ],
            ];

            // Notes:
            //
            // - Rijndael-128 is, at the same time all three of AES-128,
            //   AES-192 and AES-256. The only difference between them is
            //   the key size. Rijndael-192, Rijndael-256 on the other hand
            //   also have different block sizes and are NOT AES-compatible.
            //
            // - Blowfish is said to be supporting key sizes between
            //   4 and 56 bytes, but it appears that between MCrypt and
            //   OpenSSL, only those of 16 and more bytes are compatible.
            //   Also, don't know what MCrypt's 'blowfish-compat' is.
            //
            // - CAST-128/CAST5 produces a longer cipher when encrypted via
            //   OpenSSL, but (strangely enough) can be decrypted by either
            //   extension anyway.
            //   Also, it appears that OpenSSL uses 16 rounds regardless of
            //   the key size, while RFC2144 says that for key sizes lower
            //   than 11 bytes, only 12 rounds should be used. This makes
            //   it portable only with keys of between 11 and 16 bytes.
            //
            // - RC4 (ARCFour) has a strange implementation under OpenSSL.
            //   Its 'rc4-40' cipher method seems to work flawlessly, yet
            //   there's another one, 'rc4' that only works with a 16-byte key.
            //
            // - DES is compatible, but doesn't need an alias.
            //
            // Other seemingly matching ciphers between MCrypt, OpenSSL:
            //
            // - RC2 is NOT compatible and only an obscure forum post
            //   confirms that it is MCrypt's fault.
        }

        if (isset($dictionary[ $this->driver ][ $cipher ])) {
            $cipher = $dictionary[ $this->driver ][ $cipher ];
        }
    }

    // --------------------------------------------------------------------

    /**
     * HKDF
     *
     * @link    https://tools.ietf.org/rfc/rfc5869.txt
     *
     * @param    $key       Input key
     * @param    $digest    A SHA-2 hashing algorithm
     * @param    $salt      Optional salt
     * @param    $length    Output length (defaults to the selected digest size)
     * @param    $info      Optional context/application-specific info
     *
     * @return    string    A pseudo-random key
     */
    public function hkdf($key, $digest = 'sha512', $salt = null, $length = null, $info = '')
    {
        if ( ! isset($this->digests[ $digest ])) {
            return false;
        }

        if (empty($length) OR ! is_int($length)) {
            $length = $this->digests[ $digest ];
        } elseif ($length > (255 * $this->digests[ $digest ])) {
            return false;
        }

        self::strlen($salt) OR $salt = str_repeat("\0", $this->digests[ $digest ]);

        $prk = hash_hmac($digest, $key, $salt, true);
        $key = '';
        for ($key_block = '', $block_index = 1; self::strlen($key) < $length; $block_index++) {
            $key_block = hash_hmac($digest, $key_block . $info . chr($block_index), $prk, true);
            $key .= $key_block;
        }

        return self::substr($key, 0, $length);
    }

    // --------------------------------------------------------------------

    /**
     * Byte-safe substr()
     *
     * @param    string $str
     * @param    int    $start
     * @param    int    $length
     *
     * @return    string
     */
    protected static function substr($str, $start, $length = null)
    {
        if (self::$isFunctionOverride) {
            // mb_substr($str, $start, null, '8bit') returns an empty
            // string on PHP 5.3
            isset($length) OR $length = ($start >= 0
                ? self::strlen($str) - $start
                : -$start);

            return mb_substr($str, $start, $length, '8bit');
        }

        return isset($length)
            ? substr($str, $start, $length)
            : substr($str, $start);
    }

    // --------------------------------------------------------------------

    /**
     * Decrypt
     *
     * @param    string $data   Encrypted data
     * @param    array  $params Input parameters
     *
     * @return    string
     */
    public function decrypt($data, array $params = null)
    {
        if (($params = $this->getParams($params)) === false) {
            return false;
        }

        if (isset($params[ 'hmac_digest' ])) {
            // This might look illogical, but it is done during encryption as well ...
            // The 'base64' value is effectively an inverted "raw data" parameter
            $digest_size = ($params[ 'base64' ])
                ? $this->digests[ $params[ 'hmac_digest' ] ] * 2
                : $this->digests[ $params[ 'hmac_digest' ] ];

            if (self::strlen($data) <= $digest_size) {
                return false;
            }

            $hmac_input = self::substr($data, 0, $digest_size);
            $data = self::substr($data, $digest_size);

            isset($params[ 'hmac_key' ]) OR
            $params[ 'hmac_key' ] = $this->hkdf($this->key, 'sha512', null, null, 'authentication');
            $hmac_check = hash_hmac($params[ 'hmac_digest' ], $data, $params[ 'hmac_key' ], ! $params[ 'base64' ]);

            // Time-attack-safe comparison
            $diff = 0;
            for ($i = 0; $i < $digest_size; $i++) {
                $diff |= ord($hmac_input[ $i ]) ^ ord($hmac_check[ $i ]);
            }

            if ($diff !== 0) {
                return false;
            }
        }

        if ($params[ 'base64' ]) {
            $data = base64_decode($data);
        }

        isset($params[ 'key' ]) OR
        $params[ 'key' ] = $this->hkdf($this->key, 'sha512', null, self::strlen($this->key), 'encryption');

        return $this->{$this->driver . 'Decrypt'}($data, $params);
    }

    // --------------------------------------------------------------------

    /**
     * __get() magic
     *
     * @param    string $key Property name
     *
     * @return    mixed
     */
    public function __get($key)
    {
        // Because aliases
        if ($key === 'mode') {
            return array_search($this->mode, $this->modes[ $this->driver ], true);
        } elseif (in_array($key, ['cipher', 'driver', 'drivers', 'digests'], true)) {
            return $this->{'_' . $key};
        }

        return null;
    }

    // --------------------------------------------------------------------

    /**
     * Initialize MCrypt
     *
     * @param    array $params Configuration parameters
     *
     * @throws \O2System\Spl\Exceptions\Logic\BadFunctionCallException
     */
    protected function mcryptInitialize($params)
    {
        if ( ! empty($params[ 'cipher' ])) {
            $params[ 'cipher' ] = strtolower($params[ 'cipher' ]);
            $this->cipherAlias($params[ 'cipher' ]);

            if ( ! in_array($params[ 'cipher' ], mcrypt_list_algorithms(), true)) {
                // 'Encryption: MCrypt cipher ' . strtoupper( $params[ 'cipher' ] ) . ' is not available.'
                throw new BadFunctionCallException(
                    'E_SECURITY_MCRYPT_CIPHER_UNAVAILABLE',
                    0,
                    [strtoupper($params[ 'cipher' ])]
                );
            } else {
                $this->cipher = $params[ 'cipher' ];
            }
        }

        if ( ! empty($params[ 'mode' ])) {
            $params[ 'mode' ] = strtolower($params[ 'mode' ]);
            if ( ! isset($this->modes[ 'mcrypt' ][ $params[ 'mode' ] ])) {
                // 'Encryption: MCrypt mode ' . strtoupper( $params[ 'mode' ] ) . ' is not available.'
                throw new BadFunctionCallException(
                    'E_SECURITY_MCRYPT_MODE_UNAVAILABLE',
                    0,
                    [strtoupper($params[ 'mode' ])]
                );
            } else {
                $this->mode = $this->modes[ 'mcrypt' ][ $params[ 'mode' ] ];
            }
        }

        if (isset($this->cipher, $this->mode)) {
            if (is_resource($this->handle)
                && (strtolower(mcrypt_enc_get_algorithms_name($this->handle)) !== $this->cipher
                    OR strtolower(mcrypt_enc_get_modes_name($this->handle)) !== $this->mode)
            ) {
                mcrypt_module_close($this->handle);
            }

            if ($this->handle = mcrypt_module_open($this->cipher, '', $this->mode, '')) {
                logger(
                    'info',
                    'LOG_SECURITY_MCRYPT_CIPHER_INITIALIZED',
                    [strtoupper($this->cipher), strtoupper($this->mode)]
                );
            } else {
                throw new BadFunctionCallException(
                    'E_SECURITY_MCRYPT_UNABLE_TO_INITIALIZED',
                    0,
                    [strtoupper($this->cipher), strtoupper($this->mode)]
                );
            }
        }
    }

    // --------------------------------------------------------------------

    /**
     * Initialize OpenSSL
     *
     * @param    array $params Configuration parameters
     *
     * @throws \O2System\Spl\Exceptions\Logic\BadFunctionCallException
     */
    protected function opensslInitialize($params)
    {
        if ( ! empty($params[ 'cipher' ])) {
            $params[ 'cipher' ] = strtolower($params[ 'cipher' ]);
            $this->cipherAlias($params[ 'cipher' ]);
            $this->cipher = $params[ 'cipher' ];
        }

        if ( ! empty($params[ 'mode' ])) {
            $params[ 'mode' ] = strtolower($params[ 'mode' ]);
            if ( ! isset($this->modes[ 'openssl' ][ $params[ 'mode' ] ])) {
                // 'Encryption: OpenSSL mode ' . strtoupper( $params[ 'mode' ] ) . ' is not available.'
                throw new BadFunctionCallException(
                    'E_SECURITY_CRYPT_OPENSSL_MODE_UNAVAILABLE',
                    0,
                    [strtoupper($params[ 'mode' ])]
                );
            } else {
                $this->mode = $this->modes[ 'openssl' ][ $params[ 'mode' ] ];
            }
        }

        if (isset($this->cipher, $this->mode)) {
            // This is mostly for the stream mode, which doesn't get suffixed in OpenSSL
            $handle = empty($this->mode)
                ? $this->cipher
                : $this->cipher . '-' . $this->mode;

            if ( ! in_array($handle, openssl_get_cipher_methods(), true)) {
                $this->handle = null;
                // 'Encryption: Unable to initialize OpenSSL with method ' . strtoupper( $handle ) . '.'
                throw new BadFunctionCallException(
                    'E_SECURITY_CRYPT_OPENSSL_UNABLE_TO_INITIALIZED',
                    0,
                    [strtoupper($handle)]
                );
            } else {
                $this->handle = $handle;
                // 'Encryption: OpenSSL initialized with method ' . strtoupper( $handle ) . '.'
                logger(
                    'info',
                    'LOG_SECURITY_CRYPT_OPENSSL_INITIALIZED',
                    [strtoupper($handle)]
                );
            }
        }
    }

    // --------------------------------------------------------------------

    /**
     * Encrypt via MCrypt
     *
     * @param    string $data   Input data
     * @param    array  $params Input parameters
     *
     * @return    string
     */
    protected function mcryptEncrypt($data, $params)
    {
        if ( ! is_resource($params[ 'handle' ])) {
            return false;
        }

        // The greater-than-1 comparison is mostly a work-around for a bug,
        // where 1 is returned for ARCFour instead of 0.
        $iv = (($iv_size = mcrypt_enc_get_iv_size($params[ 'handle' ])) > 1)
            ? $this->createKey($iv_size)
            : null;

        if (mcrypt_generic_init($params[ 'handle' ], $params[ 'key' ], $iv) < 0) {
            if ($params[ 'handle' ] !== $this->handle) {
                mcrypt_module_close($params[ 'handle' ]);
            }

            return false;
        }

        // Use PKCS#7 padding in order to ensure compatibility with OpenSSL
        // and other implementations outside of PHP.
        if (in_array(strtolower(mcrypt_enc_get_modes_name($params[ 'handle' ])), ['cbc', 'ecb'], true)) {
            $block_size = mcrypt_enc_get_block_size($params[ 'handle' ]);
            $pad = $block_size - (self::strlen($data) % $block_size);
            $data .= str_repeat(chr($pad), $pad);
        }

        // Work-around for yet another strange behavior in MCrypt.
        //
        // When encrypting in ECB mode, the IV is ignored. Yet
        // mcrypt_enc_get_iv_size() returns a value larger than 0
        // even if ECB is used AND mcrypt_generic_init() complains
        // if you don't pass an IV with length equal to the said
        // return value.
        //
        // This probably would've been fine (even though still wasteful),
        // but OpenSSL isn't that dumb and we need to make the process
        // portable, so ...
        $data = (mcrypt_enc_get_modes_name($params[ 'handle' ]) !== 'ECB')
            ? $iv . mcrypt_generic($params[ 'handle' ], $data)
            : mcrypt_generic($params[ 'handle' ], $data);

        mcrypt_generic_deinit($params[ 'handle' ]);
        if ($params[ 'handle' ] !== $this->handle) {
            mcrypt_module_close($params[ 'handle' ]);
        }

        return $data;
    }

    // --------------------------------------------------------------------

    /**
     * Create a random key
     *
     * @param    int $length Browser length
     *
     * @return    string
     */
    public function createKey($length)
    {
        if (function_exists('random_bytes')) {
            try {
                return random_bytes((int)$length);
            } catch (\Exception $e) {
                logger('error', $e->getMessage());

                return false;
            }
        } elseif (defined('MCRYPT_DEV_URANDOM')) {
            return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        }

        $is_secure = null;
        $key = openssl_random_pseudo_bytes($length, $is_secure);

        return ($is_secure === true)
            ? $key
            : false;
    }

    // --------------------------------------------------------------------

    /**
     * Encrypt via OpenSSL
     *
     * @param    string $data   Input data
     * @param    array  $params Input parameters
     *
     * @return    string
     */
    protected function opensslEncrypt($data, $params)
    {
        if (empty($params[ 'handle' ])) {
            return false;
        }

        $iv = ($iv_size = openssl_cipher_iv_length($params[ 'handle' ]))
            ? $this->createKey($iv_size)
            : null;

        $data = openssl_encrypt(
            $data,
            $params[ 'handle' ],
            $params[ 'key' ],
            1, // DO NOT TOUCH!
            $iv
        );

        if ($data === false) {
            return false;
        }

        return $iv . $data;
    }

    // --------------------------------------------------------------------

    /**
     * Decrypt via MCrypt
     *
     * @param    string $data   Encrypted data
     * @param    array  $params Input parameters
     *
     * @return    string
     */
    protected function mcryptDecrypt($data, $params)
    {
        if ( ! is_resource($params[ 'handle' ])) {
            return false;
        }

        // The greater-than-1 comparison is mostly a work-around for a bug,
        // where 1 is returned for ARCFour instead of 0.
        if (($iv_size = mcrypt_enc_get_iv_size($params[ 'handle' ])) > 1) {
            if (mcrypt_enc_get_modes_name($params[ 'handle' ]) !== 'ECB') {
                $iv = self::substr($data, 0, $iv_size);
                $data = self::substr($data, $iv_size);
            } else {
                // MCrypt is dumb and this is ignored, only size matters
                $iv = str_repeat("\x0", $iv_size);
            }
        } else {
            $iv = null;
        }

        if (mcrypt_generic_init($params[ 'handle' ], $params[ 'key' ], $iv) < 0) {
            if ($params[ 'handle' ] !== $this->handle) {
                mcrypt_module_close($params[ 'handle' ]);
            }

            return false;
        }

        $data = mdecrypt_generic($params[ 'handle' ], $data);
        // Remove PKCS#7 padding, if necessary
        if (in_array(strtolower(mcrypt_enc_get_modes_name($params[ 'handle' ])), ['cbc', 'ecb'], true)) {
            $data = self::substr($data, 0, -ord($data[ self::strlen($data) - 1 ]));
        }

        mcrypt_generic_deinit($params[ 'handle' ]);
        if ($params[ 'handle' ] !== $this->handle) {
            mcrypt_module_close($params[ 'handle' ]);
        }

        return $data;
    }

    // --------------------------------------------------------------------

    /**
     * Decrypt via OpenSSL
     *
     * @param    string $data   Encrypted data
     * @param    array  $params Input parameters
     *
     * @return    string
     */
    protected function opensslDecrypt($data, $params)
    {
        if ($iv_size = openssl_cipher_iv_length($params[ 'handle' ])) {
            $iv = self::substr($data, 0, $iv_size);
            $data = self::substr($data, $iv_size);
        } else {
            $iv = null;
        }

        return empty($params[ 'handle' ])
            ? false
            : openssl_decrypt(
                $data,
                $params[ 'handle' ],
                $params[ 'key' ],
                1, // DO NOT TOUCH!
                $iv
            );
    }

    // --------------------------------------------------------------------

    /**
     * Get MCrypt handle
     *
     * @param    string $cipher Cipher name
     * @param    string $mode   Encryption mode
     *
     * @return    resource
     */
    protected function mcryptGetHandle($cipher, $mode)
    {
        return mcrypt_module_open($cipher, '', $mode, '');
    }

    // --------------------------------------------------------------------

    /**
     * Get OpenSSL handle
     *
     * @param    string $cipher Cipher name
     * @param    string $mode   Encryption mode
     *
     * @return    string
     */
    protected function opensslGetHandle($cipher, $mode)
    {
        // OpenSSL methods aren't suffixed with '-stream' for this mode
        return ($mode === 'stream')
            ? $cipher
            : $cipher . '-' . $mode;
    }
}
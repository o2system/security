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
 * Class Password
 *
 * @package O2System\Security\Encryptions
 */
class Password
{
    /**
     * Password::$salt
     *
     * Numeric encryption key.
     *
     * @var string
     */
    private $salt;

    /**
     * Password::$algorithm
     *
     * A password algorithm constant denoting the algorithm to use when hashing the password.
     *
     * @var int
     */
    private $algorithm = PASSWORD_DEFAULT;

    /**
     * Password::$options
     *
     * An associative array containing options. See the password algorithm constants for documentation on the supported
     * options for each algorithm.
     *
     * If omitted, a random salt will be created and the default cost will be used.
     *
     * @var array
     */
    private $options = [];

    // ------------------------------------------------------------------------

    /**
     * Password::setAlgorithm
     *
     * Sets password hashing algorithm.
     *
     * @see http://php.net/manual/en/password.constants.php
     *
     * @param int $algorithm A password algorithm constant denoting the algorithm to use when hashing the password.
     *
     * @return static
     */
    public function setAlgorithm($algorithm)
    {
        if (in_array(
            $algorithm,
            [
                PASSWORD_DEFAULT,
                PASSWORD_BCRYPT,
            ]
        )) {
            $this->algorithm = $algorithm;
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Password::setOptions
     *
     * Sets password hashing options.
     *
     * @see http://php.net/manual/en/password.constants.php
     *
     * @param array $options An associative array containing options. See the password algorithm constants for
     *                       documentation on the supported options for each algorithm.
     *
     * @return $this
     */
    public function setOptions(array $options)
    {
        $this->options = $options;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Password::rehash
     *
     * Re-hash a password.
     *
     * @param string $password Password to be encrypted.
     * @param string $hash     Hashed string password created by Password::hash method.
     * @param string $salt     To manually provide a salt to use when hashing the password.
     *
     * @return string|bool Returns FALSE if the password not verified.
     */
    public function rehash($password, $hash, $salt = null)
    {
        if ($this->verify($password, $hash, $salt)) {

            $algorithm = $this->algorithm === PASSWORD_DEFAULT
                ? PASSWORD_BCRYPT
                : PASSWORD_DEFAULT;

            if (password_needs_rehash(
                $hash,
                $algorithm,
                [
                    'cost' => strlen($hash) + 1,
                ]
            )) {
                return $this->hash($password, $salt);
            }

            return $hash;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Password::verify
     *
     * Verify a password.
     *
     * @param string $password Password to be verified.
     * @param string $hash     Hashed string password created by Password::hash method.
     * @param string $salt     To manually provide a salt to use when hashing the password.
     *
     * @return string
     */
    public function verify($password, $hash, $salt = null)
    {
        return password_verify($this->protect($password, $salt), $hash);
    }

    // ------------------------------------------------------------------------

    /**
     * Password::protect
     *
     * Protect a password.
     *
     * @param string $password Password to be encrypted.
     * @param string $salt     To manually provide a salt to use when hashing the password.
     *
     * @return string
     */
    protected function protect($password, $salt = null)
    {
        $salt = isset($salt)
            ? $salt
            : $this->salt;

        return $password . $salt;
    }

    // ------------------------------------------------------------------------

    /**
     * Password::hash
     *
     * Hash a password.
     *
     * @param string $password Password to be encrypted.
     * @param string $salt     To manually provide a salt to use when hashing the password.
     *
     * @return string
     */
    public function hash($password, $salt = null)
    {
        return password_hash($this->protect($password, $salt), $this->algorithm, $this->options);
    }

    // ------------------------------------------------------------------------

    /**
     * Password::setSalt
     *
     * @param string $salt Encryption key.
     *
     * @return static
     */
    protected function setSalt($salt)
    {
        $this->salt = md5($salt, true);

        return $this;
    }
}
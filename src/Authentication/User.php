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

namespace O2System\Security\Authentication;

// ------------------------------------------------------------------------

use O2System\Cache\Item;
use O2System\Spl\DataStructures\SplArrayObject;
use O2System\Spl\Traits\Collectors\ConfigCollectorTrait;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Class User
 * @package O2System\Security\Authentication
 */
class User
{
    use ConfigCollectorTrait;

    // ------------------------------------------------------------------------

    /**
     * User::__construct
     */
    public function __construct()
    {
        $this->setConfig([
            'password' => [
                'algorithm' => PASSWORD_DEFAULT,
                'options' => [],
            ],
            'msisdnRegex' => '/^\+[1-9]{1}[0-9]{3,14}$/',
            'maxAttempts' => 5,
            'sso' => [
                'enable' => false,
                'server' => base_url(),
            ],
        ]);
    }

    // ------------------------------------------------------------------------

    /**
     * User::setPasswordAlgorithm
     *
     * @param $algorithm
     *
     * @return static
     */
    public function setPasswordAlgorithm($algorithm)
    {
        if (in_array($algorithm, [PASSWORD_DEFAULT, PASSWORD_BCRYPT, PASSWORD_ARGON2I])) {
            $this->algorithm = $algorithm;
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * User::setPasswordOptions
     *
     * @param array $options
     *
     * @return static
     */
    public function setPasswordOptions(array $options)
    {
        $this->options = $options;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * User::passwordRehash
     *
     * @param string $password
     *
     * @return bool|string
     */
    public function passwordRehash($password)
    {
        if (password_needs_rehash(
            $password,
            $this->config['password']['algorithm'],
            $this->config['password']['options']
        )) {
            return $this->passwordHash($password);
        }

        return $password;
    }

    // ------------------------------------------------------------------------

    /**
     * User::passwordHash
     *
     * @param string $password
     *
     * @return bool|string
     */
    public function passwordHash($password)
    {
        return password_hash(
            $password,
            $this->config['password']['algorithm'],
            $this->config['password']['options']
        );
    }

    // ------------------------------------------------------------------------

    /**
     * User::passwordVerify
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public function passwordVerify($password, $hash)
    {
        return password_verify($password, $hash);
    }

    // ------------------------------------------------------------------------

    /**
     * User::attempt
     */
    public function attempt()
    {
        $_SESSION['userAttempts'] = $this->getAttempts() + 1;
    }

    // ------------------------------------------------------------------------

    /**
     * User::getAttempt
     *
     * @return int
     */
    public function getAttempts()
    {
        $currentAttempts = 0;
        if (isset($_SESSION['userAttempts'])) {
            $currentAttempts = (int)$_SESSION['userAttempts'];
        }

        return (int)$currentAttempts;
    }

    // ------------------------------------------------------------------------

    /**
     * User::loggedIn
     *
     * @return bool
     * @throws \Psr\Cache\InvalidArgumentException
     */
    public function loggedIn()
    {
        if (isset($_SESSION['account'])) {
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * AccessControl::login
     *
     * @param array $account
     */
    public function login(array $account)
    {
        $_SESSION['account'] = $account;
    }

    // ------------------------------------------------------------------------

    /**
     * User::logout
     */
    public function logout()
    {
        if (isset($_SESSION['account'])) {
            unset($_SESSION['account']);
        }
    }
}
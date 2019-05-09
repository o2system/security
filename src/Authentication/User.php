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
            'password'    => [
                'algorithm' => PASSWORD_DEFAULT,
                'options'   => [],
            ],
            'msisdnRegex' => '/^\+[1-9]{1}[0-9]{3,14}$/',
            'maxAttempts' => 5,
            'sso'         => [
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
            $this->config[ 'password' ][ 'algorithm' ],
            $this->config[ 'password' ][ 'options' ]
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
            $this->config[ 'password' ][ 'algorithm' ],
            $this->config[ 'password' ][ 'options' ]
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
        $_SESSION[ 'userAttempts' ] = $this->getAttempts() + 1;
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
        if (isset($_SESSION[ 'userAttempts' ])) {
            $currentAttempts = (int)$_SESSION[ 'userAttempts' ];
        }

        return (int)$currentAttempts;
    }

    // ------------------------------------------------------------------------

    /**
     * User::login
     *
     * @param array $account
     */
    public function login(array $account)
    {
        $_SESSION[ 'account' ] = $account;
        unset($_SESSION[ 'userAttempts' ]);
    }

    // ------------------------------------------------------------------------

    /**
     * User::signOn
     *
     * @param array $account
     *
     * @throws \Exception
     */
    public function signOn(array $account)
    {
        $cacheItemPool = $this->getCacheItemPool();
        $virtualUserId = md5(json_encode($account) . mt_srand() . time());
        $cacheItemPool->save(new Item('sso-' . $virtualUserId, $account, false));

        set_cookie('ssid', $virtualUserId);
    }

    // ------------------------------------------------------------------------

    /**
     * User::getCacheItemPool
     *
     * @return CacheItemPoolInterface
     */
    protected function getCacheItemPool()
    {
        $cacheItemPool = cache()->getObject('default');

        if (cache()->exists('sso')) {
            $cacheItemPool = cache()->getObject('sso');
        }

        return $cacheItemPool;
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
        if (isset($_SESSION[ 'account' ])) {
            return true;
        } elseif ($this->signedOn()) {
            $cacheItemPool = $this->getCacheItemPool();
            $item = $cacheItemPool->getItem('sso-' . input()->cookie('ssid'));
            $_SESSION[ 'account' ] = $item->get();

            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * User::signedOn
     *
     * @return bool
     * @throws \Psr\Cache\InvalidArgumentException
     */
    public function signedOn()
    {
        if ($virtualUserId = input()->cookie('ssid')) {
            $cacheItemPool = $this->getCacheItemPool();

            return $cacheItemPool->hasItem('sso-' . $virtualUserId);
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * User::logout
     */
    public function logout()
    {
        $this->signOff();

        if (isset($_SESSION[ 'account' ])) {
            unset($_SESSION[ 'account' ]);
        }
    }

    // ------------------------------------------------------------------------

    /**
     * User::signOff
     *
     * @throws \Psr\Cache\InvalidArgumentException
     */
    public function signOff()
    {
        if ($virtualUserId = input()->cookie('ssid')) {
            $cacheItemPool = $this->getCacheItemPool();
            $cacheItemPool->deleteItem('sso-' . $virtualUserId);
            delete_cookie('ssid');
        }
    }
}
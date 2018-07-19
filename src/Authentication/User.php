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

namespace O2System\Security\Authentication;

// ------------------------------------------------------------------------

use O2System\Cache\Item;
use O2System\Psr\Cache\CacheItemPoolInterface;
use O2System\Spl\Traits\Collectors\ConfigCollectorTrait;

/**
 * Class User
 * @package O2System\Security\Authentication
 */
class User
{
    use ConfigCollectorTrait;

    public function __construct()
    {
        $this->setConfig([
            'password' => [
                'algorithm' => PASSWORD_DEFAULT,
                'options' => []
            ],
            'msisdnRegex' => '/^\+[1-9]{1}[0-9]{3,14}$/',
            'maxAttempts' => 5,
            'sso' => [
                'enable' => false,
                'server' => base_url()
            ]
        ]);
    }

    public function setPasswordAlgorithm($algorithm)
    {
        if (in_array($algorithm, [PASSWORD_DEFAULT, PASSWORD_BCRYPT, PASSWORD_ARGON2I])) {
            $this->algorithm = $algorithm;
        }

        return $this;
    }

    public function setPasswordOptions(array $options)
    {
        $this->options = $options;

        return $this;
    }

    public function passwordHash($password)
    {
        return password_hash(
            $password,
            $this->config['password']['algorithm'],
            $this->config['password']['options']
        );
    }

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

    public function passwordVerify($password, $hash)
    {
        return password_verify($password, $hash);
    }

    public function attempt()
    {
        $_SESSION['userAttempts'] = $this->getAttempts() + 1;
    }

    public function getAttempts()
    {
        $currentAttempts = 0;
        if(isset($_SESSION['userAttempts'])) {
            $currentAttempts = (int) $_SESSION['userAttempts'];
        }

        return (int) $currentAttempts;
    }

    /**
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

    public function login(array $account)
    {
        $_SESSION['account'] = $account;
        unset($_SESSION['userAttempts']);
    }

    public function signOn(array $account)
    {
        $cacheItemPool = $this->getCacheItemPool();
        $virtualUserId = md5(json_encode($account) . mt_srand() . time());
        $cacheItemPool->save(new Item('sso-' . $virtualUserId, $account, false));

        set_cookie('ssid', $virtualUserId);
    }

    public function signedOn()
    {
        if($virtualUserId = input()->cookie('ssid')) {
            $cacheItemPool = $this->getCacheItemPool();
            return $cacheItemPool->hasItem('sso-' . $virtualUserId);
        }

        return false;
    }

    public function signOff()
    {
        if($virtualUserId = input()->cookie('ssid')) {
            $cacheItemPool = $this->getCacheItemPool();
            $cacheItemPool->deleteItem('sso-'  . $virtualUserId);
            delete_cookie('ssid');
        }
    }

    public function loggedIn()
    {
        if (isset($_SESSION['account'])) {
            return true;
        } elseif($this->signedOn()) {
            $cacheItemPool = $this->getCacheItemPool();
            $item = $cacheItemPool->getItem('sso-'  . input()->cookie('ssid'));
            $_SESSION['account'] = $item->get();

            return true;
        }

        return false;
    }

    public function logout()
    {
        $this->signOff();
        unset($_SESSION['account']);
    }
}
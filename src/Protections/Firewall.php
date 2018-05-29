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

// ------------------------------------------------------------------------

/**
 * Class Firewall
 *
 * @package O2System\Security\Protections
 */
class Firewall
{
    /**
     * Firewall::$ipVersion
     *
     * Filter validation ip address version.
     *
     * @var int
     */
    protected $ipVersion = FILTER_FLAG_IPV4;

    /**
     * Firewall::$whitelist
     *
     * List of whitelist Ip Addresses.
     *
     * @var array
     */
    protected $whitelistIpAddresses = [];

    /**
     * Firewall::$blacklist
     *
     * List of blacklist Ip Addresses.
     *
     * @var array
     */
    protected $blacklistIpAddresses = [];

    // ------------------------------------------------------------------------

    /**
     * Firewall::setIpVersion
     *
     * Sets filter validation ip address version.
     *
     * @param $ipVersion
     *
     * @return static
     */
    public function setIpVersion($ipVersion)
    {
        if (in_array($ipVersion, [FILTER_FLAG_IPV4, FILTER_FLAG_IPV6])) {
            $this->ipVersion = $ipVersion;
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Firewall::setWhitelistIpAddresses
     *
     * Sets whitelist ip addresses.
     *
     * @param array $ipAddresses List of whitelist ip addresses.
     *
     * @return static
     */
    public function setWhitelistIpAddresses(array $ipAddresses)
    {
        foreach ($ipAddresses as $ipAddress) {
            if ($this->isValid($ipAddress)) {
                $this->whitelistIpAddresses[] = $ipAddress;
            }
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Firewall::isValid
     *
     * Checks if the ip address is valid.
     *
     * @param string $ipAddress Ip Address.
     *
     * @return mixed
     */
    protected function isValid($ipAddress)
    {
        return filter_var($ipAddress, FILTER_FLAG_IPV4);
    }

    // ------------------------------------------------------------------------

    /**
     * Firewall::addWhitelistIpAddress
     *
     * Sets whitelist ip addresses.
     *
     * @param string $ipAddress Whitelist ip address.
     *
     * @return static
     */
    public function addWhitelistIpAddress($ipAddress)
    {
        if ($this->isValid($ipAddress)) {
            $this->whitelistIpAddresses[] = $ipAddress;
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Firewall::setBlacklistIpAddresses
     *
     * Sets whitelist ip addresses.
     *
     * @param array $ipAddresses List of whitelist ip addresses.
     *
     * @return static
     */
    public function setBlacklistIpAddresses(array $ipAddresses)
    {
        foreach ($ipAddresses as $ipAddress) {
            if ($this->isValid($ipAddress)) {
                $this->blacklistIpAddresses[] = $ipAddress;
            }
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Firewall::addBlacklistIpAddress
     *
     * Sets whitelist ip addresses.
     *
     * @param string $ipAddress Whitelist ip address.
     *
     * @return static
     */
    public function addBlacklistIpAddress($ipAddress)
    {
        if ($this->isValid($ipAddress)) {
            $this->whitelistIpAddresses[] = $ipAddress;
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Firewall::verify
     *
     * @param string $ipAddress
     *
     * @return bool
     */
    public function verify($ipAddress = null)
    {
        $ipAddress = isset($ipAddress)
            ? $ipAddress
            : input()->ipAddress();

        if ($this->isWhitelisted($ipAddress) OR
            $this->isBlacklisted($ipAddress) === false
        ) {
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Firewall::isWhitelisted
     *
     * Checks if the client ip address is whitelisted.
     *
     * @param string $ipAddress Client ip address.
     *
     * @return bool
     */
    public function isWhitelisted($ipAddress)
    {
        if ($this->isValid($ipAddress)) {
            return (bool)in_array($ipAddress, $this->whitelistIpAddresses);
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Firewall::isBlacklisted
     *
     * Checks if the client ip address is blacklisted.
     *
     * @param string $ipAddress Client ip address.
     *
     * @return bool
     */
    public function isBlacklisted($ipAddress)
    {
        if ($this->isValid($ipAddress)) {
            return (bool)in_array($ipAddress, $this->whitelistIpAddresses);
        }

        return false;
    }
}
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

namespace O2System\Security\Blockchain;

// ------------------------------------------------------------------------

/**
 * Class Block
 * @package O2System\Security\Blockchain
 */
class Block
{
    /**
     * Block::$nonce
     *
     * @var int
     */
    protected $nonce;

    /**
     * Block::$index
     *
     * @var int
     */
    protected $index;

    /**
     * Block::$timestamp
     *
     * @var int
     */
    protected $timestamp;

    /**
     * Block::$data
     *
     * @var mixed
     */
    protected $data;

    /**
     * Block::$hash
     *
     * @var string
     */
    protected $hash;

    /**
     * Block::$previousHash
     *
     * @var string
     */
    protected $previousHash;

    // ------------------------------------------------------------------------

    /**
     * Block::__construct
     */
    public function __construct($index, $timestamp, $data, $previousHash = null)
    {
        $this->setIndex($index);
        $this->setTimestamp($timestamp);
        $this->setData($data);
        $this->setPreviousHash($previousHash);

        $this->hash = $this->calculateHash();

        if(is_null($previousHash)) {
            $this->nonce = 0;
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Block::getNonce
     *
     * @return int
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::increase
     *
     * @return static
     */
    public function increase()
    {
        $this->nonce++;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::decrease
     *
     * @return static
     */
    public function decrease()
    {
        $this->nonce--;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::setIndex
     *
     * @param int $index
     *
     * @return static
     */
    public function setIndex($index)
    {
        $this->index = (int)$index;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::getIndex
     *
     * @return int
     */
    public function getIndex()
    {
        return $this->index;
    }

    /**
     * Block::setTimestamp
     *
     * @param string|int $timestamp
     *
     * @return static
     */
    public function setTimestamp($timestamp)
    {
        if (is_string($timestamp)) {
            $timestamp = strtotime($timestamp);
        }

        $this->timestamp = $timestamp;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::getTimestamp
     *
     * @return int
     */
    public function getTimestamp()
    {
        return $this->timestamp;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::setData
     *
     * @param mixed $data
     *
     * @return static
     */
    public function setData($data)
    {
        $this->data = $data;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::getData
     *
     * @return mixed
     */
    public function getData()
    {
        return $this->data;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::setPreviousHash
     *
     * @param string $previousHash
     *
     * @return static
     */
    public function setPreviousHash($previousHash)
    {
        $this->previousHash = $previousHash;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::getPreviousHash
     *
     * @return string
     */
    public function getPreviousHash()
    {
        return $this->previousHash;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::getHash
     *
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    // ------------------------------------------------------------------------

    /**
     * Block::getHash
     *
     * @return string
     */
    public function calculateHash()
    {
        $data = $this->data;
        if (is_array($this->data) or is_object($this->data)) {
            $data = json_encode($this->data);
        }

        return hash('sha256', $this->index . $this->previousHash . $this->timestamp . $data . $this->nonce);
    }

    // ------------------------------------------------------------------------

    /**
     * Block::regenerateHash
     *
     * @return string
     */
    public function regenerateHash()
    {
        $this->increase();
        $this->hash = $this->calculateHash();

        return $this->hash;
    }
}
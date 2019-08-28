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

use O2System\Security\Generators\Uuid;
use O2System\Spl\Iterators\ArrayIterator;

/**
 * Class Chain
 * @package O2System\Security\Blockchain
 */
class Chain extends ArrayIterator
{
    /**
     * Chain::$difficulty
     *
     * @var int
     */
    protected $difficulty;

    // ------------------------------------------------------------------------

    /**
     * Chain::__construct
     *
     * @param int $difficulty
     */
    public function __construct($difficulty = 4)
    {
        parent::__construct();

        $this->difficulty = $difficulty;

        // Creating Genesis Block
        $this->addBlock(new Block(0, strtotime("now"), 'GENESIS_BLOCK ' . Uuid::generate()));
    }

    // ------------------------------------------------------------------------

    /**
     * Chain::addBlock
     *
     * @param \O2System\Security\Blockchain\Block $block
     */
    public function addBlock(Block $block)
    {
        if ($this->count()) {
            $lastBlock = $this->last();

            if ($lastBlock instanceof Block) {
                $block->setPreviousHash($lastBlock->getHash());

                $this->mine($block);
                $this->push($block);
            }
        } else {
            $this->push($block);
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Chain::mine
     *
     * @param \O2System\Security\Blockchain\Block $block
     */
    public function mine(Block $block)
    {
        while (substr($block->getHash(), 0, $this->difficulty) !== str_repeat('0', $this->difficulty)) {
            $block->regenerateHash();
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Chain::isValid
     *
     * Validates the blockchain's integrity.
     *
     * @return bool Returns FALSE if the blockchain integrity is invalid.
     */
    public function isValid()
    {
        for ($i = 1; $i < $this->count(); $i++) {
            $currentBlock = $this->offsetGet($i);
            $previousBlock = $this->offsetGet($i - 1);

            if ($currentBlock instanceof Block) {
                if ($currentBlock->getHash() != $currentBlock->calculateHash()) {
                    return false;
                }

                if ($previousBlock instanceof Block) {
                    if ($currentBlock->getPreviousHash() != $previousBlock->getHash()) {
                        return false;
                    }
                }
            }
        }

        return true;
    }
}
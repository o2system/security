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

namespace O2System\Security\Protections\Oauth\Interfaces;

// ------------------------------------------------------------------------

/**
 * Interface ProviderModelInterface
 * @package O2System\Security\Protections\Oauth\Interfaces
 */
interface ProviderModelInterface
{
    public function findConsumer(array $condition);

    // ------------------------------------------------------------------------

    public function findToken(array $condition);

    // ------------------------------------------------------------------------

    public function insertToken(array $token);

    // ------------------------------------------------------------------------

    public function updateToken(array $token, array $condition);
}
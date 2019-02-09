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

namespace O2System\Security\Authentication\Oauth\Client;

// ------------------------------------------------------------------------

use O2System\Security\Authentication\Oauth;

/**
 * Class Credential
 * @package O2System\Security\Authentication\Oauth\Client
 */
class Credential
{
    /**
     * Credential::getSecretCode
     *
     * @param \O2System\Security\Authentication\Oauth\Client\Account $client
     * @param array                                                  $options
     */
    public function getSecretCode(Oauth\Client\Account $client, array $options = [])
    {
        $scope = $this->config[ 'scope' ];
        if (isset($options[ 'scope' ])) {
            if (is_array($options[ 'scope' ])) {
                $scope = array_merge($scope, $options[ 'scope' ]);
            }
        }

        $params = [
            'scope'         => $scope,
            'state'         => $this->state,
            'client_id'     => $client->id,
            'redirect_uri'  => $this->redirect_uri,
            'response_type' => $this->response_type,
        ];
    }

    // ------------------------------------------------------------------------
}
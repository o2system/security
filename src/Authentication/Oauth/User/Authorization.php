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

namespace O2System\Security\Authentication\Oauth\User;

// ------------------------------------------------------------------------

use O2System\Security\Authentication;
use O2System\Security\Authentication\Oauth;
use O2System\Security\Generators\Token;
use O2System\Spl\Traits\Collectors\ConfigCollectorTrait;

/**
 * Class Authorization
 * @package O2System\Security\Authentication\Oauth\User
 */
class Authorization
{
    use ConfigCollectorTrait;

    /**
     * Authorization::$user
     *
     * @var \O2System\Security\Authentication\Oauth\User\Account
     */
    protected $user;

    // ------------------------------------------------------------------------

    /**
     * Authorization::__construct
     *
     * @param \O2System\Security\Authentication\Oauth\User\Account $user
     */
    public function __construct(Oauth\User\Account $user)
    {
        $this->user = $user;

        $this->setConfig([
            'issuer'    => null,
            'scope'     => [],
            'authorize' => [
                'allow_implicit'             => false,
                'enforce_state'              => true,
                'require_exact_redirect_uri' => true,
                'redirect_status_code'       => 302,
            ],
            'token'     => [
                'type'             => 'bearer',
                'lifetime'         => 3600,
                'refresh_lifetime' => 1209600,
            ],
        ]);
    }

    // ------------------------------------------------------------------------

    /**
     * Authorization::getRefreshToken
     *
     * Provide an unique refresh token
     *
     * Implementing classes may want to override this function to implement
     * other refresh token generation schemes.
     *
     * @param \O2System\Security\Authentication\Oauth\Client\Account $client
     * @param array                                                  $options
     *
     * @return array
     * @throws \Exception
     */
    public function getRefreshToken(Oauth\Client\Account $client, array $options = [])
    {
        return $this->getAccessToken($client, $options); // let's reuse the same scheme for token generation
    }

    // ------------------------------------------------------------------------

    /**
     * Authorization::getAccessToken
     *
     * Provide an unique access token.
     *
     * Implementing classes may want to override this function to implement
     * other access token generation schemes.
     *
     * @param \O2System\Security\Authentication\Oauth\Client\Account $client
     * @param array                                                  $options
     *
     * @return array
     * @throws \Exception
     */
    public function getAccessToken(Oauth\Client\Account $client, array $options = [])
    {
        $privateKey = null;
        if ($client->offsetExists('private_key')) {
            $privateKey = $client->offsetGet('private_key');
        }

        $scope = $this->config[ 'token' ][ 'scope' ];
        if (isset($options[ 'scope' ])) {
            if (is_array($options[ 'scope' ])) {
                $scope = array_merge($scope, $options[ 'scope' ]);
            }
        }

        if (isset($options[ 'lifetime' ])) {
            $this->config[ 'token' ][ 'lifetime' ] = $options[ 'lifetime' ];
        }

        if (isset($options[ 'refresh_lifetime' ])) {
            $this->config[ 'token' ][ 'refresh_lifetime' ] = $options[ 'refresh_lifetime' ];
        }

        $payload = $this->createPayload($client, $scope);

        $jsonWebToken = new Authentication\JsonWebToken();
        $accessToken = $jsonWebToken->encode($payload, $privateKey);

        return [
            "access_token" => $accessToken,
            "expires_in"   => $this->config[ 'token' ][ 'lifetime' ],
            "token_type"   => $this->config[ 'token' ][ 'type' ],
            "scope"        => $payload[ 'scope' ],
        ];
    }

    // ------------------------------------------------------------------------

    /**
     * Authorization::createPayload
     *
     * @param \O2System\Security\Authentication\Oauth\Client\Account $client
     * @param array                                                  $scope
     *
     * @return array
     * @throws \Exception
     */
    protected function createPayload(Oauth\Client\Account $client, array $scope = [])
    {
        // token to encrypt
        $expires = time() + $this->config[ 'token' ][ 'lifetime' ];

        $id = Token::generate(40, Token::ALPHAHASH_STRING);
        $payload = [
            'id'         => $id,
            // the internal id of the token
            'jti'        => $id,
            // a unique token identifier for the token (JWT ID)
            'iss'        => $this->config[ 'issuer' ],
            // the id of the server who issued the token (Issuer)
            'aud'        => $client->id,
            // the id of the client who requested the token (Audience)
            'sub'        => ($this->user->offsetExists('id') ? $this->user->offsetGet('id') : null),
            // the id of the user for which the token was released (Subject)
            'exp'        => $expires,
            'iat'        => time(),
            'token_type' => $this->config[ 'token' ][ 'type' ],
            'scope'      => empty($scope) ? null : implode(' ', $scope),
        ];

        if ($client->offsetExists('metadata')) {
            if (is_array($client->metadata)) {
                $payload = array_merge($client->metadata, $payload);
            }
        }

        return $payload;
    }
}
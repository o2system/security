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

namespace O2System\Security\Protections\Oauth;

// ------------------------------------------------------------------------

use O2System\Security\Protections\Oauth\Datastructures;
use O2System\Security\Protections\Oauth\Interfaces\ProviderModelInterface;
use O2System\Spl\Traits\Collectors\ErrorCollectorTrait;

/**
 * Class Provider
 * @package O2System\Security\Protections\Oauth
 */
class Provider
{
    use ErrorCollectorTrait;

    /**
     * Provider::$oauth
     *
     * @var \OAuthProvider
     */
    protected $oauth;

    /**
     * Provider::$consumer
     *
     * @var \O2System\Security\Protections\Oauth\Datastructures\Consumer
     */
    protected $consumer;

    /**
     * Provider::$token
     *
     * @var \O2System\Security\Protections\Oauth\Datastructures\Token
     */
    protected $token;

    /**
     * Provider::$model
     *
     * @var \O2System\Security\Protections\Oauth\Interfaces\ProviderModelInterface
     */
    protected $model;

    // ------------------------------------------------------------------------

    /**
     * Provider::__construct
     */
    public function __construct()
    {
        language()
            ->addFilePath(str_replace('Protections' . DIRECTORY_SEPARATOR . 'Oauth', '', __DIR__) . DIRECTORY_SEPARATOR)
            ->loadFile('oauth');

        $this->oauth = new \OAuthProvider([
            'signature_method' => 'HMAC-SHA1',
        ]);

        $this->oauth->consumerHandler([$this, 'handleConsumer']);
        $this->oauth->timestampNonceHandler([$this, 'handleTimestampNonce']);
        $this->oauth->tokenHandler([$this, 'handleToken']);

        if (models()->has('oauth')) {
            $this->modelHander(models()->get('oauth'));
        }

        $this->oauth->signature_method = OAUTH_SIG_METHOD_HMACSHA1;
        $this->oauth->consumer_key = input()->get('consumer_key');
        $this->oauth->consumer_secret = input()->get('consumer_secret');
        $this->oauth->token = input()->get('oauth_token');
        $this->oauth->token_secret = input()->get('oauth_token_secret');
        $this->oauth->token_type = null;

        // Get HTTP_AUTHORIZATION
        if ($httpAuthorization = input()->server('HTTP_AUTHORIZATION')) {
            $httpAuthorization = explode(' ', $httpAuthorization);
            $httpAuthorization = array_map('trim', $httpAuthorization);

            switch (strtoupper($httpAuthorization[ 0 ])) {
                default:
                case 'OAUTH':
                    array_shift($httpAuthorization);
                    $httpAuthorization = array_map(function ($string) {
                        $string = str_replace(['"', ','], '', $string);
                        $string = explode('=', $string);

                        return [
                            'key'   => str_replace('oauth_', '', $string[ 0 ]),
                            'value' => $string[ 1 ],
                        ];
                    }, $httpAuthorization);

                    $oauthParams = [];
                    foreach ($httpAuthorization as $param) {
                        $oauthParams[ $param[ 'key' ] ] = $param[ 'value' ];
                    }

                    $this->oauth->signature_method = $oauthParams[ 'signature_method' ];
                    $this->oauth->nonce = $oauthParams[ 'nonce' ];
                    $this->oauth->timestamp = $oauthParams[ 'timestamp' ];
                    $this->oauth->consumer_key = $oauthParams[ 'consumer_key' ];
                    $this->oauth->version = $oauthParams[ 'version' ];

                    if (isset($oauthParams[ 'callback' ])) {
                        $this->oauth->callback = urldecode($oauthParams[ 'callback' ]);
                    }

                    if (isset($oauthParams[ 'signature' ])) {
                        $this->oauth->signature = $oauthParams[ 'signature' ];
                    }

                    $this->oauth->callconsumerHandler();
                    break;
                case 'BASIC':
                case 'BEARER':
                    $this->oauth->bearer = $httpAuthorization[ 1 ];
                    $bearer = base64_decode($this->oauth->bearer);
                    $bearer = explode(':', $bearer);
                    $bearer = array_map('trim', $bearer);

                    if (count($bearer) == 2) {
                        $this->oauth->consumer_key = $bearer[ 0 ];
                        $this->oauth->consumer_secret = $bearer[ 1 ];

                        $this->oauth->callconsumerHandler();
                    }

                    break;
            }
        } elseif ($oauthVerifier = input()->post('oauth_verifier')) {
            $this->oauth->verifier = $oauthVerifier;
            $verifier = base64_decode($this->oauth->verifier);
            $verifier = explode(':', $verifier);
            $verifier = array_map('trim', $verifier);

            if (count($verifier) == 2) {
                $this->oauth->token = $verifier[ 0 ];
                $this->oauth->token_secret = $verifier[ 1 ];
            }
        }

        if ( ! empty($this->oauth->token)) {
            $this->oauth->calltokenHandler();
        }

        if ( ! $this->hasErrors()) {
            if ( ! empty($this->oauth->timestamp) && ! empty($this->oauth->nonce)) {
                $this->oauth->callTimestampNonceHandler();
            }
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::modelHandler
     *
     * Sets OAuth Provider model handler.
     *
     * @param $model
     *
     * @return void
     */
    public function modelHander(ProviderModelInterface $model)
    {
        $this->model = $model;
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::getAccessToken
     *
     * Gets OAuth Access Token.
     *
     * @return array|bool|\O2System\Security\Protections\Oauth\Datastructures\Token
     */
    public function getAccessToken()
    {
        if ( ! empty($this->token)) {
            if ($this->model->insertTokenNonce([
                'id_consumer_token' => $this->token->id,
                'nonce'             => $token[ 'nonce' ] = Oauth::generateNonce(),
                'timestamp'         => $token[ 'timestamp' ] = date('Y-m-d H:m:s'),
                'expires'           => $token[ 'expires' ] = time() + 3600,
            ])) {
                return new Datastructures\Token([
                    'key'       => $this->token->key,
                    'secret'    => $this->token->secret,
                    'nonce'     => $token[ 'nonce' ],
                    'timestamp' => $token[ 'timestamp' ],
                    'expires'   => $token[ 'expires' ],
                    'verifier'  => (new Token($this->token->key, $this->token->secret))->getVerifier(),
                ]);
            }
        }

        $token = $this->generateToken('ACCESS');
        $token = new Datastructures\Token([
            'id'       => $token[ 'id' ],
            'key'      => $token[ 'key' ],
            'secret'   => $token[ 'secret' ],
            'verifier' => (new Token($token[ 'key' ], $token[ 'secret' ]))->getVerifier(),
        ]);

        if ($this->model->insertTokenNonce([
            'id_consumer_token' => $token[ 'id' ],
            'nonce'             => $token[ 'nonce' ] = Oauth::generateNonce(),
            'timestamp'         => $token[ 'timestamp' ] = date('Y-m-d H:m:s'),
            'expires'           => $token[ 'expires' ] = time() + 3600,
        ])) {
            return $token;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::generateToken
     *
     * @param string $type
     * @param int    $length
     * @param bool   $strong
     *
     * @return array|bool Returns FALSE if failed.
     */
    protected function generateToken($type = 'ACCESS', $length = 32, $strong = true)
    {
        if ( ! empty($this->consumer->secret)) {
            if (false !== ($token = $this->model->findToken([
                    'id_consumer' => $this->consumer->id,
                    'type'        => $type,
                ]))) {
                $this->oauth->nonce = $token->nonce;

                return [
                    'id'     => $token->id,
                    'key'    => $token->key,
                    'secret' => $token->secret,
                ];
            } else {
                switch ($this->oauth->signature_method) {
                    default:
                    case OAUTH_SIG_METHOD_HMACSHA1:
                    case OAUTH_SIG_METHOD_RSASHA1:

                        $token = [
                            'key'    => hash_hmac('sha1', \OAuthProvider::generateToken($length, $strong),
                                $this->consumer->secret),
                            'secret' => hash_hmac('sha1', \OAuthProvider::generateToken($length, $strong),
                                $this->consumer->secret),
                        ];
                        break;

                    case OAUTH_SIG_METHOD_HMACSHA256:

                        $token = [
                            'key'    => hash_hmac('sha256', \OAuthProvider::generateToken($length, $strong),
                                $this->consumer->secret),
                            'secret' => hash_hmac('sha256', \OAuthProvider::generateToken($length, $strong),
                                $this->consumer->secret),
                        ];
                        break;
                }

                $nonce = (empty($this->oauth->nonce) ? Oauth::generateNonce() : $this->oauth->nonce);
                $callback = (empty($this->oauth->callback) ? null : $this->oauth->callback);

                if ($this->model->insertToken([
                    'id_consumer' => $this->consumer->id,
                    'key'         => $token[ 'key' ],
                    'secret'      => $token[ 'secret' ],
                    'type'        => $type,
                    'callback'    => $callback,
                ])) {
                    $token[ 'id' ] = $this->model->db->getLastInsertId();

                    if ($this->model->insertTokenNonce([
                        'id_consumer_token' => $token[ 'id' ],
                        'nonce'             => $nonce,
                        'timestamp'         => date('Y-m-d H:m:s'),
                        'expires'           => time() + 3600,
                    ])) {
                        return $token;
                    }
                }
            }
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::getRequestToken
     *
     * Gets OAuth Request Token.
     *
     * @return array|bool Returns FALSE if failed.
     */
    public function getRequestToken()
    {
        return $this->generateToken('REQUEST');
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::handleConsumer
     *
     * OAuth Consumer Handler.
     *
     * @param \OAuth $provider
     *
     * @return int
     */
    public function handleConsumer($provider)
    {
        $this->consumer = new Datastructures\Consumer();

        if (false !== ($consumer = $this->model->findConsumer(['key' => $provider->consumer_key]))) {
            $this->consumer->id = $consumer->id;
            $this->consumer->key = $consumer->key;
            $this->consumer->secret = $provider->consumer_secret = $consumer->secret;
            $this->consumer->status = $consumer->status;

            if ($consumer->status === 'ENABLED') {
                return OAUTH_OK;
            }

            $this->addError(OAUTH_CONSUMER_KEY_REFUSED, language()->getLine('OAUTH_CONSUMER_KEY_REFUSED'));

            return OAUTH_CONSUMER_KEY_REFUSED;
        }

        if (empty($this->oauth->bearer)) {
            $this->addError(OAUTH_CONSUMER_KEY_UNKNOWN, language()->getLine('OAUTH_CONSUMER_KEY_UNKNOWN'));
        } else {
            $this->addError(OAUTH_CONSUMER_KEY_UNKNOWN, language()->getLine('OAUTH_AUTHORIZATION_UNKNOWN'));
        }

        return OAUTH_CONSUMER_KEY_UNKNOWN;
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::revokeToken
     *
     * Revoke OAuth Consumer Token.
     *
     * @param string $token oauth_token
     *
     * @return bool
     */
    public function revokeToken($token)
    {
        $this->oauth->token = $token;
        $this->oauth->calltokenHandler();

        if ( ! $this->hasErrors()) {
            return $this->model->deleteToken(['key' => $token]);
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::handleToken
     *
     * OAuth Token Handler.
     *
     * @param \OAuth $provider
     *
     * @return int
     */
    public function handleToken($provider)
    {
        if (false !== ($token = $this->model->findToken(['key' => $provider->token]))) {
            if (isset($token->consumer)) {
                $this->token = $token;

                $this->consumer = $token->consumer;
                $provider->consumer_key = $this->consumer->key;
                $provider->consumer_secret = $this->consumer->secret;
                $provider->token_secret = $token->secret;
            }

            return OAUTH_OK;
        }

        if (empty($this->oauth->verifier)) {
            $this->addError(OAUTH_TOKEN_REJECTED, language()->getLine('OAUTH_TOKEN_REJECTED'));

            return OAUTH_TOKEN_REJECTED;
        } else {
            $this->addError(OAUTH_VERIFIER_INVALID, language()->getLine('OAUTH_TOKEN_VERIFIER_REJECTED'));

            return OAUTH_VERIFIER_INVALID;
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::handleTimestampNonce
     *
     * OAuth Timestamp and Nonce Handler.
     *
     * @param \OAuth $provider
     *
     * @return int
     */
    public function handleTimestampNonce($provider)
    {
        if (empty($provider->timestamp)) {
            $this->addError(OAUTH_BAD_TIMESTAMP, language()->getLine('OAUTH_BAD_TIMESTAMP'));

            return OAUTH_BAD_TIMESTAMP;
        }

        if (false !== ($token = $this->model->findTokenNonce([
                'nonce' => $provider->nonce,
            ]))) {
            if (time() > $token->expires) {
                $this->addError(OAUTH_TOKEN_EXPIRED, language()->getLine('OAUTH_TOKEN_EXPIRED'));

                return OAUTH_TOKEN_EXPIRED;
            }

            return OAUTH_OK;
        }

        $this->addError(OAUTH_BAD_NONCE, language()->getLine('OAUTH_BAD_NONCE'));

        return OAUTH_BAD_NONCE;
    }

    // ------------------------------------------------------------------------

    /**
     * Provider::isValidRequest
     *
     * Determine if the OAuth Request is valid.
     *
     * @return bool
     */
    public function isValidRequest()
    {
        $message = language()->getLine('OAUTH_SIGNATURE_METHOD_REJECTED');

        if (empty($this->oauth->callback)) {
            $consumer = new Consumer($this->oauth->consumer_key, $this->oauth->consumer_secret);

            $signature = $consumer->getSignature(
                $this->oauth->signature_method,
                null,
                null,
                [
                    'oauth_nonce'            => $this->oauth->nonce,
                    'oauth_signature_method' => $this->oauth->signature_method,
                    'oauth_timestamp'        => $this->oauth->timestamp,
                    'oauth_consumer_key'     => $this->oauth->consumer_key,
                    'oauth_version'          => $this->oauth->version,
                ]);

            if ($signature === $this->oauth->signature) {
                return true;
            }
        } elseif (empty($this->oauth->signature)) {
            $message = language()->getLine('OAUTH_SIGNATURE_MISSING');
        } else {
            $consumer = new Consumer($this->oauth->consumer_key, $this->oauth->consumer_secret);

            $signature = $consumer->getSignature(
                $this->oauth->signature_method,
                $this->oauth->callback,
                input()->server('REQUEST_METHOD'),
                [
                    'oauth_nonce'            => $this->oauth->nonce,
                    'oauth_signature_method' => $this->oauth->signature_method,
                    'oauth_timestamp'        => $this->oauth->timestamp,
                    'oauth_consumer_key'     => $this->oauth->consumer_key,
                    'oauth_version'          => $this->oauth->version,
                ]);

            if ($signature === $this->oauth->signature) {
                return true;
            }
        }

        $this->addError(OAUTH_SIGNATURE_METHOD_REJECTED, $message);

        return false;
    }
}
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
 * Class HttpAuthentication
 *
 * @package O2System\Security\Protections
 */
class HttpAuthentication
{
    /**
     * HttpAuthentication::AUTH_BASIC
     *
     * Basic Realm HTTP Authentication.
     *
     * @var int
     */
    const AUTH_BASIC = 1;

    /**
     * HttpAuthentication::AUTH_DIGEST
     *
     * Digest HTTP Authentication.
     *
     * @var int
     */
    const AUTH_DIGEST = 2;

    /**
     * HttpAuthentication::$type
     *
     * HTTP authentication type.
     *
     * @var int
     */
    private $type;

    /**
     * HttpAuthentication::$realm
     *
     * HTTP authentication realm.
     *
     * @var string
     */
    private $realm;

    /**
     * HttpAuthentication::$authenticate
     *
     * HTTP authentication validation.
     *
     * @var \Closure
     */
    private $validation;

    /**
     * HttpAuthentication::$users
     *
     * List of users access.
     *
     * @var array
     */
    private $users = [];

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::__construct
     */
    public function __construct($realm, $type = HttpAuthentication::AUTH_BASIC)
    {
        $this->setRealm($realm)
            ->setType($type);

        if (class_exists('\O2System\Framework')) {
            if ($security = config()->getItem('security')) {
                if ($security->offsetExists('httpAuthentication')) {
                    $this->users = $security->offsetGet('httpAuthentication');
                }
            } elseif (false !== ($users = config()->loadFile('HttpAuthentication'))) {
                $this->users = $users;
            }
        }
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::setType
     *
     * Sets WWW-Authenticate Type
     *
     * @param int $type WWW-Authenticate Type.
     *
     * @return static
     */
    public function setType($type)
    {
        if (in_array($type, [self::AUTH_BASIC, self::AUTH_DIGEST])) {
            $this->type = $type;
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::setRealm
     *
     * Sets WWW-Authenticate Realm
     *
     * @param string $realm WWW-Authenticate Realm.
     *
     * @return static
     */
    public function setRealm($realm)
    {
        $this->realm = trim($realm);

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::setUsers
     *
     * Sets WWW-Authenticate Users.
     *
     * @param array $users WWW-Authenticate Users.
     *
     * @return static
     */
    public function setUsers(array $users)
    {
        $this->users = $users;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::setUsersValidation
     *
     * Sets WWW-Authenticate Validation.
     *
     * @param \Closure $closure WWW-Authenticate Validation Callback.
     *
     * @return static
     */
    public function setUsersValidation(\Closure $closure)
    {
        $this->validation = $closure;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::verify
     *
     * Verify client access based on request headers.
     *
     * @return bool
     */
    public function verify()
    {
        switch ($this->type) {
            default:
            case self::AUTH_BASIC:

                if ($authorization = input()->server('HTTP_AUTHORIZATION')) {
                    $authentication = unserialize(base64_decode($authorization));
                    if ($this->login($authentication[ 'username' ], $authentication[ 'password' ])) {
                        return true;
                    }
                } else {
                    $authentication = $this->parseBasic();
                }

                if ($this->login($authentication[ 'username' ], $authentication[ 'password' ])) {

                    header('Authorization: Basic ' . base64_encode(serialize($authentication)));

                    return true;
                } else {
                    unset($_SERVER[ 'PHP_AUTH_USER' ], $_SERVER[ 'PHP_AUTH_PW' ]);
                    $this->protect();
                }

                break;
            case self::AUTH_DIGEST:
                if ($authorization = input()->server('HTTP_AUTHORIZATION')) {
                    $authentication = $this->parseDigest($authorization);
                } elseif ($authorization = input()->server('PHP_AUTH_DIGEST')) {
                    $authentication = $this->parseDigest($authorization);
                }

                if (isset($authentication) AND
                    false !== ($password = $this->login($authentication[ 'username' ]))
                ) {
                    $A1 = md5($authentication[ 'username' ] . ':' . $this->realm . ':' . $password);
                    $A2 = md5($_SERVER[ 'REQUEST_METHOD' ] . ':' . $authentication[ 'uri' ]);
                    $response = md5(
                        $A1
                        . ':'
                        . $authentication[ 'nonce' ]
                        . ':'
                        . $authentication[ 'nc' ]
                        . ':'
                        . $authentication[ 'cnonce' ]
                        . ':'
                        . $authentication[ 'qop' ]
                        . ':'
                        . $A2
                    );

                    if ($authentication[ 'response' ] === $response) {
                        header(
                            sprintf(
                                'Authorization: Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s", opaque="%s"',
                                $authentication[ 'username' ],
                                $this->realm,
                                $authentication[ 'nonce' ],
                                $authentication[ 'uri' ],
                                $authentication[ 'qop' ],
                                $authentication[ 'nc' ],
                                $authentication[ 'cnonce' ],
                                $response,
                                $authentication[ 'opaque' ]
                            )
                        );

                        return true;
                    }
                }

                unset($_SERVER[ 'PHP_AUTH_DIGEST' ], $_SERVER[ 'HTTP_AUTHORIZATION' ]);
                $this->protect();

                break;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::login
     *
     * Perform WWW-Authenticate Login.
     *
     * @param string $username Authentication username.
     * @param string $password Authentication password.
     *
     * @return bool|string
     */
    public function login($username, $password = null)
    {
        switch ($this->type) {
            default:
            case self::AUTH_BASIC:
                if (isset($username) AND isset($password)) {
                    if ($this->validation instanceof \Closure) {
                        return call_user_func_array($this->validation, func_get_args());
                    } else {
                        if (array_key_exists($username, $this->users)) {
                            if ($this->users[ $username ] === $password) {
                                return true;
                            }
                        }
                    }
                }
                break;
            case self::AUTH_DIGEST:
                if (isset($username)) {
                    if ($this->validation instanceof \Closure) {
                        return call_user_func_array($this->validation, func_get_args());
                    } else {
                        if (array_key_exists($username, $this->users)) {
                            return $this->users[ $username ];
                        }
                    }
                }
                break;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::parseBasic
     *
     * Parse Basic Realm HTTP Authentication data.
     *
     * @return array Basic Realm HTTP Authentication data.
     */
    protected function parseBasic()
    {
        return [
            'username' => input()->server('PHP_AUTH_USER'),
            'password' => input()->server('PHP_AUTH_PW'),
        ];
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::protect
     *
     * Protect requested page with HTTP Authorization form dialog.
     *
     * @return void
     */
    protected function protect()
    {
        header('HTTP/1.1 401 Unauthorized');

        switch ($this->type) {
            default:
            case self::AUTH_BASIC:
                header('WWW-Authenticate: Basic realm="' . $this->realm . '"');
                break;
            case self::AUTH_DIGEST:
                header(
                    'WWW-Authenticate: Digest realm="' . $this->realm .
                    '", qop="auth", nonce="' . md5(uniqid()) . '", opaque="' . md5(uniqid()) . '"'
                );
                break;
        }
    }

    // ------------------------------------------------------------------------

    /**
     * HttpAuthentication::parseBasic
     *
     * Parse Digest HTTP Authentication data.
     *
     * @param string $digest Authentication Digest.
     *
     * @return array Digest HTTP Authentication data.
     */
    protected function parseDigest($digest)
    {
        $digest = str_replace('Digest ', '', $digest);
        $digest = trim($digest);

        $parts = explode(',', $digest);
        $parts = array_map('trim', $parts);

        $data = [];
        foreach ($parts as $part) {
            $elements = explode('=', $part);
            $elements = array_map(
                function ($element) {
                    return trim(str_replace('"', '', $element));

                },
                $elements
            );

            $data[ $elements[ 0 ] ] = $elements[ 1 ];
        }

        return empty($data)
            ? false
            : $data;
    }
}
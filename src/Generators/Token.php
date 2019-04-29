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

namespace O2System\Security\Generators;

// ------------------------------------------------------------------------

use O2System\Security\Encoders\Base64;
use O2System\Security\Encoders\Json;
use O2System\Security\Encryptions\Algorithm;
use O2System\Spl\Traits\Collectors\ErrorCollectorTrait;

/**
 * Class Token
 *
 * Security token generator.
 *
 * @package O2System\Security\Generators
 */
class Token
{
    use ErrorCollectorTrait;

    /**
     * Token::ALPHANUMERIC_STRING
     *
     * @var int
     */
    const ALPHANUMERIC_STRING = 0;

    /**
     * Token::ALPHAUPPERCASE_STRING
     *
     * @var int
     */
    const ALPHAUPPERCASE_STRING = 1;

    /**
     * Token::ALPHALOWERCASE_STRING
     *
     * @var int
     */
    const ALPHALOWERCASE_STRING = 2;

    /**
     * Token::ALPHAHASH_STRING
     *
     * @var int
     */
    const ALPHAHASH_STRING = 3;

    /**
     * Token::NUMERIC_STRING
     *
     * @var int
     */
    const NUMERIC_STRING = 4;

    /**
     * Token::$key
     *
     * @var string|null
     */
    protected $key = null;

    /**
     * Allow the current timestamp to be specified.
     * Useful for fixing a value within unit testing.
     *
     * Will default to PHP time() value if null.
     */
    protected $timestamp;

    /**
     * Token::$algorithm
     *
     * @var string
     */
    protected $algorithm = 'HMAC-SHA256';

    /**
     * Token::$headers
     *
     * @var array
     */
    protected $headers = [];

    // ------------------------------------------------------------------------

    /**
     * Token::__construct
     */
    public function __construct()
    {
        if (class_exists('O2System\Framework', false)) {
            $this->key = config()->getItem('security')->encryptionKey;
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Token::generate
     *
     * @param int $length Token string length.
     * @param int $type   Token string type.
     *
     * @return string
     * @throws \Exception
     */
    public static function generate($length = 8, $type = self::ALPHANUMERIC_STRING)
    {
        if ($type !== self::ALPHAHASH_STRING) {
            switch ($type) {
                default:
                case self::ALPHANUMERIC_STRING:
                    $codeAlphabet = implode(range('A', 'Z')); // Uppercase Alphabet
                    $codeAlphabet .= implode(range('a', 'z')); // Lowercase Alphabet
                    $codeAlphabet .= implode(range(0, 9)); // Numeric Alphabet
                    break;
                case self::ALPHAUPPERCASE_STRING:
                    $codeAlphabet = implode(range('A', 'Z')); // Uppercase Alphabet
                    break;
                case self::ALPHALOWERCASE_STRING:
                    $codeAlphabet = implode(range('a', 'z')); // Lowercase Alphabet
                    break;
                case self::NUMERIC_STRING:
                    $codeAlphabet = implode(range(0, 9)); // Numeric Alphabet
                    break;
            }

            $token = '';
            $max = strlen($codeAlphabet);

            for ($i = 0; $i < $length; $i++) {
                $token .= $codeAlphabet[ random_int(0, $max - 1) ];
            }

            return $token;
        }

        /**
         * ALPHABIN2HEX_STRING
         */
        if (function_exists('random_bytes')) {
            $randomData = random_bytes(20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        if (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        if (function_exists('mcrypt_create_iv')) {
            $randomData = mcrypt_create_iv(20, MCRYPT_DEV_URANDOM);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        if (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        // Last resort which you probably should just get rid of:
        $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);

        return substr(hash('sha512', $randomData), 0, $length);
    }

    // ------------------------------------------------------------------------

    /**
     * Token::setKey
     *
     * @param string $key
     *
     * @return static
     */
    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Token::setAlgorithm
     *
     * @param string $algorithm
     *
     * @return static
     */
    public function setAlgorithm($algorithm)
    {
        $algorithm = strtoupper($algorithm);

        if (Algorithm::validate($algorithm)) {
            $this->algorithm = $algorithm;
        }

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Token::setTimestamp
     *
     * @param int|string $timestamp
     *
     * @return static
     */
    public function setTimestamp($timestamp)
    {
        $this->timestamp = is_numeric($timestamp) ? $timestamp : strtotime($timestamp);

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Token::encode
     *
     * @param array $payload
     * @param null  $key
     *
     * @return string
     * @throws \O2System\Spl\Exceptions\Logic\DomainException
     */
    public function encode(array $payload, $key = null)
    {
        $key = empty($key) ? $this->key : $key;

        $this->addHeader('algorithm', $this->algorithm);

        // Create Header Segment
        $segments[] = Base64::encode(Json::encode($this->headers));

        // Create Payload Segment
        $segments[] = Base64::encode(Json::encode($payload));

        // Create Signature Segment
        $segments[] = Base64::encode(Signature::generate($segments, $key, $this->algorithm));

        return implode('.', $segments);
    }

    // ------------------------------------------------------------------------

    /**
     * Token::addHeader
     *
     * @param string $key
     * @param mixed  $value
     *
     * @return static
     */
    public function addHeader($key, $value)
    {
        $this->headers[ $key ] = $value;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Token::decode
     *
     * @param string $token
     * @param null   $key
     *
     * @return bool|\O2System\Spl\DataStructures\SplArrayObject|string|null
     */
    public function decode($token, $key = null)
    {
        $key = empty($key) ? $this->key : $key;

        $timestamp = empty($this->timestamp) ? time() : $this->timestamp;

        $segments = explode('.', $token);
        $segments = array_map('trim', $segments);

        if (count($segments) == 3) {
            list($headers, $payload, $signature) = $segments;

            // Base64 decode headers
            if (false === ($headers = Base64::decode($headers))) {
                $this->errors[] = 'Invalid header base64 decoding';

                return false;
            }

            // Json decode headers
            if (null === ($headers = Json::decode($headers))) {
                $this->errors[] = 'Invalid header json decoding';

                return false;
            }

            // Validate algorithm header
            if (empty($headers->alg)) {
                $this->errors[] = 'Invalid algorithm';

                return false;
            } elseif ( ! Algorithm::validate($headers->alg)) {
                $this->errors[] = 'Unsupported algorithm';

                return false;
            }

            // Base64 decode payload
            if (false === ($payload = Base64::decode($payload))) {
                $this->errors[] = 'Invalid payload base64 decoding';

                return false;
            }

            // Json decode payload
            if (null === ($payload = Json::decode($payload))) {
                $this->errors[] = 'Invalid payload json decoding';

                return false;
            }

            // Base64 decode payload
            if (false === ($signature = Base64::decode($signature))) {
                $this->errors[] = 'Invalid signature base64 decoding';

                return false;
            }

            if (Signature::verify($token, $signature, $key, $headers->alg) === false) {
                $this->errors[] = 'Invalid signature';

                return false;
            }

            // Check if the nbf if it is defined. This is the time that the
            // token can actually be used. If it's not yet that time, abort.
            if (isset($payload->nbf) && $payload->nbf > $timestamp) {
                $this->errors[] = 'Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload->nbf);

                return false;
            }

            // Check that this token has been created before 'now'. This prevents
            // using tokens that have been created for later use (and haven't
            // correctly used the nbf claim).
            if (isset($payload->iat) && $payload->iat > $timestamp) {
                $this->errors[] = 'Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload->iat);

                return false;
            }
            // Check if this token has expired.
            if (isset($payload->exp) && $timestamp >= $payload->exp) {
                $this->errors[] = 'Expired token';

                return false;
            }

            return $payload;
        }

        return false;
    }
}
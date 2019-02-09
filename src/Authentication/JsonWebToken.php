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

namespace O2System\Security\Authentication;

// ------------------------------------------------------------------------

use O2System\Security\Encoders\Base64;
use O2System\Security\Encoders\Json;
use O2System\Security\Generators\Signature;
use O2System\Security\Generators\Token;

/**
 * Class JsonWebToken
 * @package O2System\Security\Authentication
 */
class JsonWebToken extends Token
{
    protected $keyId;

    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     */
    protected $leeway = 0;

    protected $headers = [
        'typ' => 'JWT',
    ];

    // ------------------------------------------------------------------------

    public function setKeyId($keyId)
    {
        $this->keyId = $keyId;

        return $this;
    }

    // ------------------------------------------------------------------------

    public function setLeeway($leeway)
    {
        $this->leeway = intval($leeway);

        return $this;
    }

    // ------------------------------------------------------------------------

    public function encode(array $payload, $key = null)
    {
        $key = empty($key) ? $this->key : $key;
        if (is_null($key)) {
            if (class_exists('O2System\Framework', false)) {
                $key = config()->getItem('security')->encryptionKey;
            }
        }

        $this->addHeader('alg', $this->algorithm);

        if ( ! empty($this->keyId)) {
            $this->addHeader('kid', $this->keyId);
        }

        // Create Header Segment
        $segments[] = Base64::encode(Json::encode($this->headers));

        // Create Payload Segment
        $segments[] = Base64::encode(Json::encode($payload));

        // Create Signature Segment
        $segments[] = Base64::encode(Signature::generate($segments, $key, $this->algorithm));

        return implode('.', $segments);
    }

    // ------------------------------------------------------------------------

    public function decode($token, $key = null)
    {
        $key = empty($key) ? $this->key : $key;
        if (is_null($key)) {
            if (class_exists('O2System\Framework', false)) {
                $key = config()->getItem('security')->encryptionKey;
            }
        }

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
            } elseif ( ! Signature::validAlgorithm($headers->alg)) {
                $this->errors[] = 'Unsupported algorithm';

                return false;
            }

            // Validate algorithm key id
            if (is_array($key) or $key instanceof \ArrayAccess) {
                if (isset($headers->kid)) {
                    if ( ! isset($key[ $headers->kid ])) {
                        $this->errors[] = 'Invalid Key Id';

                        return false;
                    }

                    $key = $key[ $headers->kid ];
                } else {
                    $this->errors[] = 'Empty Key id';

                    return false;
                }
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
            if (isset($payload->nbf) && $payload->nbf > ($timestamp + $this->leeway)) {
                $this->errors[] = 'Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload->nbf);

                return false;
            }

            // Check that this token has been created before 'now'. This prevents
            // using tokens that have been created for later use (and haven't
            // correctly used the nbf claim).
            if (isset($payload->iat) && $payload->iat > ($timestamp + $this->leeway)) {
                $this->errors[] = 'Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload->iat);

                return false;
            }
            // Check if this token has expired.
            if (isset($payload->exp) && ($timestamp - $this->leeway) >= $payload->exp) {
                $this->errors[] = 'Expired token';

                return false;
            }

            return $payload;
        }

        return false;
    }
}
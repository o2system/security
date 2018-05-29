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

use O2System\Spl\Exceptions\RuntimeException;

/**
 * Class Captcha
 *
 * @package O2System\Security\Protections
 */
class Captcha
{
    /**
     * Captcha::$token
     *
     * Active CAPTCHA protection token.
     *
     * @var string
     */
    private $token;

    // ------------------------------------------------------------------------

    /**
     * Captcha::__construct
     */
    public function __construct()
    {
        language()
            ->addFilePath(str_replace('Protections', '', __DIR__) . DIRECTORY_SEPARATOR)
            ->loadFile('captcha');

        if (false === ($this->token = $this->getToken())) {
            $this->regenerate();
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Captcha::getToken
     *
     * Gets CAPTCHA protection token string.
     *
     * @return string|bool Returns FALSE if not set.
     */
    protected function getToken()
    {
        if (isset($_SESSION[ 'captchaToken' ])) {
            return $_SESSION[ 'captchaToken' ];
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Captcha::regenerate
     *
     * Regenerate CAPTCHA protection token.
     *
     * @return string Base64 image string.
     */
    public function regenerate()
    {
        $_SESSION[ 'captchaToken' ] = $this->token = strtoupper(
            substr(
                md5(
                    uniqid(
                        mt_rand(),
                        true
                    ) . 'CAPTCHA'
                ),
                2,
                6
            )
        );

        return $this->getImage();
    }

    // ------------------------------------------------------------------------

    /**
     * Captcha::getImage
     *
     * Gets CAPTCHA protection token image.
     *
     * @return string Base64 image string.
     * @throws \O2System\Spl\Exceptions\RuntimeException
     */
    public function getImage()
    {
        if (class_exists('O2System\Framework')) {
            $tempFilePath = @tempnam(PATH_CACHE, 'captcha');
        } else {
            $tempFilePath = @tempnam(
                sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'o2system' . DIRECTORY_SEPARATOR,
                'captcha'
            );
        }

        if ($image = imagecreatetruecolor(200, 50)) {
            $backgroundColor = imagecolorallocate($image, 255, 255, 255);
            $lineColor = imagecolorallocate($image, 64, 64, 64);
            $pixelColor = imagecolorallocate($image, 0, 0, 255);

            imagefilledrectangle($image, 0, 0, 200, 50, $backgroundColor);

            for ($i = 0; $i < 3; $i++) {
                imageline($image, 0, rand() % 50, 200, rand() % 50, $lineColor);
            }

            for ($i = 0; $i < 1000; $i++) {
                imagesetpixel($image, rand() % 200, rand() % 50, $pixelColor);
            }

            $textColor = imagecolorallocate($image, 0, 0, 0);

            for ($i = 0; $i < 6; $i++) {
                imagestring($image, 10, 20 + ($i * 30), 20, substr($this->getToken(), $i, 1), $textColor);
            }

            imagepng($image, $tempFilePath);

            $base64Image = base64_encode(file_get_contents($tempFilePath));
            @unlink($tempFilePath);

            return 'data:image/png;base64,' . $base64Image;
        }

        // Cannot Initialize new GD image stream
        throw new RuntimeException('SECURITY_E_CAPTCHA_GD_IMAGE_STREAM');
    }

    // ------------------------------------------------------------------------

    /**
     * Captcha::isValid
     *
     * Checks if the posted CAPTCHA protection token is valid.
     *
     * @param string $token Captcha token.
     *
     * @return bool
     */
    public function verify($token = null)
    {
        $token = isset($token)
            ? $token
            : input()->postGet('captchaToken');

        if (false !== ($this->getToken() === $token)) {
            return true;
        }

        return false;
    }
}
<?php

declare(strict_types=1);

namespace Laminas\Captcha;

use Laminas\ReCaptcha\ReCaptcha as ReCaptchaService;

use function array_key_exists;
use function is_array;
use function is_int;
use function is_string;

/**
 * ReCaptcha adapter
 *
 * Allows to insert captchas driven by ReCaptcha service
 *
 * @see http://recaptcha.net/apidocs/captcha/
 */
class ReCaptcha extends AbstractAdapter
{
    private ReCaptchaService $service;

    public const string MISSING_VALUE = 'missingValue';
    public const string ERR_CAPTCHA   = 'errCaptcha';
    public const string BAD_CAPTCHA   = 'badCaptcha';

    /**
     * Error messages
     *
     * @var array
     */
    protected $messageTemplates = [
        self::MISSING_VALUE => 'Missing captcha fields',
        self::ERR_CAPTCHA   => 'Failed to validate captcha',
        self::BAD_CAPTCHA   => 'Captcha value is wrong',
    ];

    public function __construct(ReCaptchaService $service)
    {
        $this->service = $service;
        parent::__construct();
    }

    /**
     * Generate captcha
     *
     * @see AbstractAdapter::generate()
     *
     * @return string
     */
    public function generate(): string
    {
        return "";
    }

    /**
     * Validate captcha.
     *
     * The value should contain the name of the key within the context that
     * contains the ReCaptcha data. The default within the ReCaptcha service
     * for this is "g-recaptcha-response"
     *
     * @see    \Laminas\Validator\ValidatorInterface::isValid()
     *
     * @param  mixed $value
     * @param  mixed $context
     * @return bool
     */
    public function isValid($value, $context = null)
    {
        if (empty($value) && ! is_array($context)) {
            $this->error(self::MISSING_VALUE);
            return false;
        }

        if ((is_string($value) || is_int($value)) && array_key_exists($value, $context)) {
            $response = $this->service->verify($context[$value]);
        } else {
            $response = $this->service->verify($value);
        }

        if (!$response->isValid()) {
            $this->error(self::BAD_CAPTCHA);
            return false;
        }

        return true;
    }

    /**
     * Get helper name used to render captcha
     *
     * @return string
     */
    public function getHelperName()
    {
        return "captcha/recaptcha";
    }
}

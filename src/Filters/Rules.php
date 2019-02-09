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

namespace O2System\Security\Filters;

// ------------------------------------------------------------------------

use O2System\Spl\Exceptions\Logic\OutOfRangeException;
use O2System\Spl\Traits\Collectors\ErrorCollectorTrait;

/**
 * Class Rules
 *
 * @package O2System\Security\Filters
 */
class Rules
{
    use ErrorCollectorTrait;

    /**
     * Rules Clauses
     *
     * @access  protected
     * @type    array
     */
    protected $clauses = [];

    /**
     * Rules Custom Error Messages
     *
     * @access  protected
     * @type    array
     */
    protected $customErrors = [];

    /**
     * Source Variables
     *
     * @access  protected
     * @type    array
     */
    protected $sourceVars = [];

    // ------------------------------------------------------------------------

    /**
     * Rules::__construct
     *
     * @param array $sourceVars
     */
    public function __construct($sourceVars = [])
    {
        language()
            ->addFilePath(__DIR__ . DIRECTORY_SEPARATOR)
            ->loadFile('rules')
            ->loadFile('validation');

        $this->customErrors = [
            'required'  => language()->getLine('SECURITY_RULES_E_REQUIRED'),
            'float'     => language()->getLine('SECURITY_RULES_E_FLOAT'),
            'email'     => language()->getLine('SECURITY_RULES_E_EMAIL'),
            'integer'   => language()->getLine('SECURITY_RULES_E_INTEGER'),
            'minLength' => language()->getLine('SECURITY_RULES_E_MINLENGTH'),
            'maxLength' => language()->getLine('SECURITY_RULES_E_MAXLENGTH'),
            'listed'    => language()->getLine('SECURITY_RULES_E_LISTED'),
        ];

        if ( ! empty($sourceVars)) {
            if ($sourceVars instanceof \ArrayObject) {
                $sourceVars = $sourceVars->getArrayCopy();
            }

            $this->sourceVars = $sourceVars;
        }
    }

    /**
     * Rules::setSource
     *
     * @param array $sourceVars
     */
    public function setSource(array $sourceVars)
    {
        $this->sourceVars = $sourceVars;
    }

    // --------------------------------------------------------------------------------------

    /**
     * Rules::addSource
     *
     * @param string $key
     * @param string $value
     */
    public function addSource($key, $value)
    {
        $this->sourceVars[ $key ] = $value;
    }

    // --------------------------------------------------------------------

    /**
     * Rules::sets
     *
     * @param array $rules
     */
    public function sets(array $rules)
    {
        foreach ($rules as $rule) {
            $this->add($rule[ 'field' ], $rule[ 'label' ], $rule[ 'rules' ], $rule[ 'messages' ]);
        }
    }

    // --------------------------------------------------------------------

    /**
     * Rules::add
     *
     * @param string $field
     * @param string $label
     * @param string $rules
     * @param array  $messages
     */
    public function add($field, $label, $rules, $messages = [])
    {
        $this->clauses[ $field ] = [
            'field'    => $field,
            'label'    => $label,
            'rules'    => $rules,
            'messages' => $messages,
        ];
    }

    // --------------------------------------------------------------------

    /**
     * Rules::has
     *
     * @param $field
     *
     * @return bool
     */
    public function has($field)
    {
        if (array_key_exists($field, $this->clauses)) {
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------------

    /**
     * Rules::setMessage
     *
     * @param string $field
     * @param string $message
     */
    public function setMessage($field, $message)
    {
        $this->customErrors[ $field ] = $message;
    }

    // ------------------------------------------------------------------------

    /**
     * Rules::validate
     *
     * @return bool
     * @throws \O2System\Spl\Exceptions\Logic\OutOfRangeException
     */
    public function validate()
    {
        if (count($this->sourceVars) == 0) {
            $this->addError(1, language()->getLine('SECURITY_RULES_E_DATA_SOURCE_EMPTY'));

            return false;
        }

        foreach ($this->clauses as $fieldName => $fieldParams) {

            /* Throw exception if existed rules field not yet exists in data source */
            if ( ! array_key_exists($fieldName, $this->sourceVars)) {
                throw new OutOfRangeException('SECURITY_RULES_E_HEADER_OUTOFRANGEEXCEPTION', 1);
            }

            if (is_string($fieldParams[ 'rules' ])) {
                /**
                 * Explode field rules by | as delimiter
                 */
                $fieldRules = explode('|', $fieldParams[ 'rules' ]);

                foreach ($fieldRules as $fieldRuleMethod) {
                    /* Get parameter from given data */
                    $fieldValue = $this->sourceVars[ $fieldName ];
                    if ( ! is_array($fieldValue)) {
                        $fieldValue = [$fieldValue];
                    }

                    if (empty($fieldValue)) {
                        array_unshift($fieldValue, null);
                    }

                    /* Check if rules has parameter */
                    if (preg_match_all("/\[(.*)\]/", $fieldRuleMethod, $fieldRuleParams)) {

                        /* Remove [] from method */
                        $fieldRuleMethod = preg_replace("/\[.*\]/", '', $fieldRuleMethod);

                        /* Explode rule parameter */
                        $fieldRuleParams = explode(',', preg_replace("/,[ ]+/", ',', $fieldRuleParams[ 1 ][ 0 ]));

                        if ($fieldRuleMethod === 'match') {
                            foreach ($fieldRuleParams as $fieldRuleParamKey => $fieldRuleParamValue) {
                                if (array_key_exists($fieldRuleParamValue, $this->sourceVars)) {
                                    $fieldRuleParams[ $fieldRuleParamKey ] = $this->sourceVars[ $fieldRuleParamValue ];
                                }
                            }
                        } elseif ($fieldRuleMethod === 'listed') {
                            $fieldRuleParams = [$fieldRuleParams];
                        }

                        /* Merge method's param with field rule's params */
                        $fieldValue = array_merge($fieldValue, $fieldRuleParams);
                    }

                    $validationClass = new Validation;
                    $validationMethod = 'is' . studlycase($fieldRuleMethod);
                    $validationStatus = false;

                    /* Throw exception if method not exists in validation class */
                    if (method_exists($validationClass, $validationMethod)) {
                        $validationStatus = call_user_func_array([&$validationClass, $validationMethod], $fieldValue);
                    } elseif (function_exists($fieldRuleMethod)) {
                        $validationStatus = call_user_func_array($fieldRuleMethod, $fieldValue);
                    } elseif (is_callable($fieldRuleMethod)) {
                        $validationStatus = call_user_func_array($fieldRuleMethod, $fieldValue);
                    }

                    if ($validationStatus === false) {
                        if ( ! empty($fieldParams[ 'messages' ])) {
                            $message = $fieldParams[ 'messages' ];

                            /* If $rule message is array, replace $message with specified message */
                            if (is_array($fieldParams[ 'messages' ])) {
                                if (isset($fieldParams[ 'messages' ][ $fieldRuleMethod ])) {
                                    $message = $fieldParams[ 'messages' ][ $fieldRuleMethod ];
                                } else {
                                    $message = $fieldParams[ 'messages' ][ $fieldName ];
                                }
                            }
                        } elseif (array_key_exists($fieldName, $this->customErrors)) {
                            $message = $this->customErrors[ $fieldName ];
                        } elseif (array_key_exists($fieldRuleMethod, $this->customErrors)) {
                            $message = $this->customErrors[ $fieldRuleMethod ];
                        } else {
                            $message = 'RULE_' . strtoupper($fieldRuleMethod);
                        }

                        /* Replace message placeholder, :attribute, :params */
                        $message = str_replace(':attribute',
                            (isset($fieldParams[ 'label' ]) ? $fieldParams[ 'label' ] : $fieldName), $message);
                        if (isset($fieldRuleParams) AND ! empty($fieldRuleParams[ 0 ])) {
                            $message = str_replace(':params', implode(',', $fieldRuleParams), $message);
                        }

                        $this->setFieldError($fieldName, language($fieldParams[ 'label' ]),
                            language($message, [$fieldValue]));
                    }

                }
            }
        }

        return empty($this->errors) ? true : false;
    }

    // --------------------------------------------------------------------------------------

    /**
     * Rules::setFieldError
     *
     * @param string $field
     * @param string $label
     * @param string $message
     */
    protected function setFieldError($field, $label, $message)
    {
        $this->errors[ $field ] = [
            'label'   => $label,
            'message' => $message,
        ];
    }

    // --------------------------------------------------------------------------------------

    /**
     * Rules::displayErrors
     *
     * @return array|string
     */
    public function displayErrors()
    {
        if (class_exists('O2System\Framework', false)) {
            $ul = new \O2System\Framework\Libraries\Ui\Contents\Lists\Unordered();

            foreach ($this->getErrors() as $field => $errorParams) {
                $ul->createList($errorParams[ 'label' ] . ': ' . $errorParams[ 'message' ]);
            }

            return $ul->render();
        }

        return $this->getErrors();
    }
}
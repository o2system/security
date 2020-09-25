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

namespace O2System\Security\Form;

// ------------------------------------------------------------------------

use O2System\Spl\Traits\Collectors\ErrorCollectorTrait;

/**
 * Class Validator
 * @package O2System\Security\Form
 */
class Validator
{
    use ErrorCollectorTrait;

    /**
     * Validator::$rules
     *
     * @var array
     */
    protected $rules;

    /**
     * Validator::$customRules
     *
     * The custom rules callbacks.
     *
     * @var array
     */
    protected $customRules = [];

    /**
     * Validator::$customErrors
     *
     * @var array
     */
    protected $customErrors = [];

    // ------------------------------------------------------------------------

    /**
     * Validator::setRules
     *
     * Stores the rules that should be used to validate the items.
     * Rules should be an array formatted like:
     *
     *    [
     *        'field' => 'rule1|rule2'
     *    ]
     *
     * The $customErrors array should be formatted like:
     *    [
     *        'field' => [
     *            'rule1' => 'message',
     *            'rule2' => 'message
     *        ],
     *    ]
     *
     * @param array $rules
     * @param array $customErrors An array of custom error messages
     *
     * @return static
     */
    public function setRules(array $rules, array $customErrors = [])
    {
        $this->setCustomErrors($customErrors);

        foreach ($rules as $field => &$rule) {
            if (is_array($rule)) {
                if (array_key_exists('errors', $rule)) {
                    $this->customErrors[ $field ] = $rule[ 'errors' ];
                    unset($rule[ 'errors' ]);
                }
            }
        }

        $this->rules = $rules;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::addRule
     *
     * Sets an individual rule and custom error messages for a single field.
     *
     * The custom error message should be just the messages that apply to
     * this field, like so:
     *
     *    [
     *        'rule' => 'message',
     *        'rule' => 'message'
     *    ]
     *
     * @param string      $field
     * @param string|null $label
     * @param string      $rules
     * @param array       $customErrors
     *
     * @return $this
     */
    public function addRule(string $field, string $label = null, string $rules, array $customErrors = [])
    {
        $this->rules[ $field ] = [
            'label' => $label,
            'rules' => $rules,
        ];

        $this->customErrors = array_merge($this->customErrors, [
            $field => $customErrors,
        ]);

        return $this;
    }
    //--------------------------------------------------------------------

    /**
     * Validator::getRules
     *
     * @return array
     */
    public function getRules()
    {
        return $this->rules;
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::hasRule
     *
     * Checks to see if the rule for key $field has been set or not.
     *
     * @param string $field
     *
     * @return bool
     */
    public function hasRule(string $field)
    {
        return array_key_exists($field, $this->rules);
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::setCustomRules
     *
     * [
     *      'rule' => function($value) {
     *           // do something here
     *           return true;
     *      }
     * ]
     *
     * @param array $customRules
     *
     * @return static
     */
    public function setCustomRules(array $customRules)
    {
        $this->customRules = $customRules;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::addCustomRule
     *
     * @param string   $rule
     * @param callable $customRule
     *
     * @return static
     */
    public function addCustomRule(string $rule, callable $customRule)
    {
        $this->customRules[ $rule ] = $customRule;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::setCustomErrors
     *
     * The custom error message should be just the messages that apply to
     * this field, like so:
     *
     *    [
     *        'field' => [
     *             'rule' => 'message',
     *             'rule' => 'message'
     *        ]
     *    ]
     *
     *
     * @param array $customErrors An array of custom error messages
     *
     * @return static
     */
    public function setCustomErrors(array $customErrors)
    {
        $this->customErrors = $customErrors;

        return $this;
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::getCustomErrors
     *
     * @return array
     */
    public function getCustomErrors()
    {
        return $this->customErrors;
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::splitRules
     *
     * Split rules string by pipe operator.
     *
     * @param string $rules
     *
     * @return array
     */
    protected function splitRules(string $rules): array
    {
        $nonEscapeBracket = '((?<!\\\\)(?:\\\\\\\\)*[\[\]])';
        $pipeNotInBracket = sprintf(
            '/\|(?=(?:[^\[\]]*%s[^\[\]]*%s)*(?![^\[\]]*%s))/',
            $nonEscapeBracket,
            $nonEscapeBracket,
            $nonEscapeBracket
        );

        $splittedRules = preg_split(
            $pipeNotInBracket,
            $rules
        );

        return array_unique($splittedRules);
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::validate
     *
     * @param array $data
     *
     * @return bool
     */
    public function validate(array $data, $singleField = false)
    {
        // If no rules exist, we return false to ensure
        // the developer didn't forget to set the rules.
        if (empty($this->rules)) {
            return false;
        }

        foreach ($this->rules as $ruleField => $ruleSetup) {
            // Blast $ruleSetup apart, unless it's already an array.
            $rules = $ruleSetup[ 'rules' ] ?? $ruleSetup;

            if (is_string($rules)) {
                $rules = $this->splitRules($rules);
            }

            $value = dot_array_search($ruleField, $data);

            $this->processRules($ruleField, $ruleSetup[ 'label' ] ?? $ruleField, $value ?? null, $rules, $data);
        }

        return ! empty($this->errors) ? false : true;
    }

    // ------------------------------------------------------------------------

    /**
     * Validator::processRules
     *
     * Runs all of $rules against $field, until one fails, or
     * all of them have been processed. If one fails, it adds
     * the error to $this->errors and moves on to the next,
     * so that we can collect all of the first errors.
     *
     * @param string      $field
     * @param string|null $label
     * @param string      $value
     * @param array|null  $rules
     * @param array       $data // All of the fields to check.
     *
     * @return boolean
     */
    protected function processRules(string $field, string $label = null, $value, $rules = null, array $data)
    {
        // If the if_exist rule is defined...
        if (in_array('if_exist', $rules)) {
            // and the current field does not exists in the input data
            // we can return true. Ignoring all other rules to this field.
            if ( ! array_key_exists($field, $data)) {
                return true;
            }

            // Otherwise remove the if_exist rule and continue the process
            $rules = array_diff($rules, ['if_exist']);
        }

        if (in_array('nullable', $rules)) {
            if ( ! in_array('required', $rules) && (is_array($value) ? empty($value) : (trim($value) === ''))) {
                return true;
            }

            $rules = array_diff($rules, ['nullable']);
        }

        if (in_array('optional', $rules)) {
            if ( ! in_array('required', $rules) && (is_array($value) ? empty($value) : (trim($value) === ''))) {
                return true;
            }

            $rules = array_diff($rules, ['optional']);
        }

        $validation = new Validation();

        foreach ($rules as $rule) {
            // Rules is callable
            $callable = is_callable($rule);

            // Rules passed
            $passed = false;

            // Rules can contain parameters: max_length[5]
            $params = false;

            // Placeholder for custom errors from the rules.
            $error = null;

            if ( ! $callable && preg_match('/(.*?)\[(.*)\]/', $rule, $match)) {
                $rule = $match[ 1 ];
                $params = $match[ 2 ];
            }

            if ($params) {
                $params = array_merge([$value], $params);
            } else {
                $params = [$value];
            }

            // If it's a callable, call and and get out of here.
            if ($callable) {
                $passed = call_user_func_array($rule, $params);
            } elseif (isset($this->customRules[ $field ])) {
                $passed = call_user_func_array($this->customRules[ $rule ], $params);
            } elseif (method_exists($validation, $validationRuleMethod = 'is' . studlycase($rule))) {
                $passed = call_user_func_array([&$validation, $validationRuleMethod], $params);
            }

            // Set the error message if we didn't survive.
            if ($passed === false) {
                if (isset($this->customErrors[ $field ][ $rule ])) {
                    $error = $this->customErrors[ $field ][ $rule ];
                }

                $this->errors[ $field ] = is_null($error) ? $this->getErrorMessage($rule, $field, $label,
                    $params) : $error;

                return false;
            }
        }

        return true;
    }
    //--------------------------------------------------------------------

    /**
     * Check; runs the validation process, returning true or false
     * determining whether validation was successful or not.
     *
     * @param mixed    $value        Value to validation.
     * @param string   $rule         Rule.
     * @param string[] $customErrors Errors.
     *
     * @return boolean True if valid, else false.
     */
    public function check($value, string $rule, array $customErrors = []): bool
    {
        $this->reset();
        $this->setRule('check', null, $rule, $customErrors);

        return $this->run([
            'check' => $value,
        ]);
    }
    //--------------------------------------------------------------------

    /**
     * Validator::getError
     *
     * Returns the error(s) for a specified $field (or empty string if not
     * set).
     *
     * @param string $field Field.
     *
     * @return string Error(s).
     */
    public function getError(string $field = null): string
    {
        if ($field === null && count($this->rules) === 1) {
            reset($this->rules);
            $field = key($this->rules);
        }

        return array_key_exists($field, $this->getErrors()) ? $this->errors[ $field ] : '';
    }
    //--------------------------------------------------------------------

    /**
     * Attempts to find the appropriate error message
     *
     * @param string      $rule
     * @param string      $field
     * @param string|null $label
     * @param string      $param
     *
     * @return string
     */
    protected function getErrorMessage(string $rule, string $field, string $label = null, string $param = null): string
    {
        // Check if custom message has been defined by user
        if (isset($this->customErrors[ $field ][ $rule ])) {
            $message = $this->customErrors[ $field ][ $rule ];
        } else {
            // Try to grab a localized version of the message...
            // lang() will return the rule name back if not found,
            // so there will always be a string being returned.
            $message = language('E_SECURITY_RULE_' . strtoupper($rule));
        }

        $message = str_replace('{field}', $label ?? $field, $message);
        $message = str_replace('{param}', $this->rules[ $param ][ 'label' ] ?? $param, $message);

        return $message;
    }
    //--------------------------------------------------------------------

    /**
     * Validator::reset
     *
     * Resets the class to a blank slate. Should be called whenever
     * you need to process more than one array.
     *
     * @return static
     */
    protected function reset()
    {
        $this->rules = [];
        $this->customErrors = [];
        $this->errors = [];

        return $this;
    }
}
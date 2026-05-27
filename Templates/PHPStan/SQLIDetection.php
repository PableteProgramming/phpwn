<?php

/**
 * SQL Injection Detection Rule for PHPStan
 * 
 * This rule detects potential SQL injection vulnerabilities in calls to $db->query()
 * where the query argument is built using dynamic strings.
 * 
 * DETECTION STRATEGY (Conservative / Over-approximate):
 * - Flags ANY variable, superglobal, function call, method call, or property access
 *   that appears in a concatenation or interpolated string inside query()
 * 
 * HANDLED NODE TYPES:
 * - Variable           ($id)
 * - ArrayDimFetch      ($_GET['id'], $_POST['user']['name'])
 * - Concat             ("SELECT ... " . $var)
 * - InterpolatedString ("SELECT ... $var")
 * - FuncCall           (getUserId(), trim($_GET['id']))
 * - MethodCall         ($db->quote($_GET['id']), $user->getName())
 * - StaticCall         (User::getTable())
 * - PropertyFetch      ($user->name)
 * - StaticPropertyFetch (Config::$dbTable)
 * 
 * FUNCTION HANDLING:
 * - Known functions (trim, strtolower, intval, etc.) -> check their arguments recursively
 * - Unknown functions -> always trigger (conservative)
 * - Safe functions (none for SQL) -> array is empty
 * 
 * LIMITATIONS (Why Psalm is needed):
 * - No flow awareness – cannot trace if a variable was sanitized or came from safe source
 * - No taint tracking – cannot distinguish user input from hardcoded values
 * - Over-approximates – many false positives expected
 * 
 * ROLE IN PIPELINE:
 * - Stage 1: Syntactic pattern matching
 * - Output: All locations where query() uses dynamic strings
 * - Stage 2: Psalm taint analysis filters false positives
 */

namespace $NAMESPACE;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Scalar\InterpolatedString;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PhpParser\Node\Identifier;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\InterpolatedStringPart;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticPropertyFetch;

/**
 * @implements Rule<MethodCall>
 */
class SQLIDetection implements Rule
{
    //functions that are known safe, no trigger
    private $safeFunctions = [
    ];

    //functions with known behaviour, check for user controlled arguments
    private $knownFunctions = [
        // String manipulation
        'trim',
        'ltrim',
        'rtrim',
        'strtolower',
        'strtoupper',
        'ucfirst',
        'lcfirst',
        'ucwords',
        'str_replace',
        'str_ireplace',
        'substr',
        'str_split',
        'implode',
        'explode',
        'sprintf',
        'vsprintf',

        // Encoding / decoding
        'addslashes',
        'stripslashes',
        'urlencode',
        'urldecode',
        'rawurlencode',
        'rawurldecode',
        'html_entity_decode',
        'base64_encode',
        'base64_decode',

        // Validation / sanitization (weak/useless in SQLI)
        'filter_var',
        'htmlspecialchars',
        'htmlentities',

        // Mathematical / casting
        'intval',
        'floatval',
        'doubleval',
        'abs',
        'ceil',
        'floor',
        'round',

        // Hashing / encoding
        'md5',
        'sha1',
        'hash',
        'json_encode',
        'serialize',

        // String padding / repetition
        'str_pad',
        'str_repeat'
    ];

    public function getNodeType(): string
    {
        return MethodCall::class;
    }

    private function isSafeFunction(FuncCall $node, string $type): array
    {
        if (in_array($node->name->name, $this->safeFunctions, true)) {
            //is is a safe function
            return [];
        } elseif (in_array($node->name->name, $this->knownFunctions, true)) {
            //we check for the arguments
            $result = [];
            foreach ($node->args as $arg) {
                $result = array_merge($result, $this->isSecure($arg->value, $type));
            }
            return $result;
        }
        //an unsafe and unknown function was used
        return [
            RuleErrorBuilder::message('Potential SQLI: unsafe function \'' . $node->name->name . '\' called.')
                ->identifier("security.sqli")
                ->build()
        ];
    }

    private function getVariableBaseName(ArrayDimFetch|PropertyFetch $node): string
    {
        if ($node->var instanceof Variable) {
            return $node->var->name;
        } elseif (get_class($node) === get_class($node->var)) {
            //recursively call the function
            return $this->getVariableBaseName($node->var);
        }
        // we cannot handle all edges cases...the most important is that we trigger an error...the variable name is not that important.
        return "?";
    }

    private function getStaticPropertyClassName(StaticPropertyFetch $node): string
    {
        if ($node->class instanceof Node\Name) {
            return $node->class->toString();
        }
        if ($node->class instanceof Node\Expr\Variable) {
            return '$' . $node->class->name;
        }
        return '?';
    }

    private function isSecure(Node $node, string $type): array
    {
        $result = [];
        if ($node instanceof Variable) {
            array_push(
                $result,
                RuleErrorBuilder::message('Potential SQLI: unsafe use of the variable $' . $node->name . ' in ' . $type . '.')
                    ->identifier("security.sqli")
                    ->build()
            );
        } elseif ($node instanceof Concat) {
            //it is a concat
            $result = array_merge($result, $this->isSecure($node->left, $type));
            $result = array_merge($result, $this->isSecure($node->right, $type));
        } elseif ($node instanceof ArrayDimFetch) {
            $varName = $this->getVariableBaseName($node);
            array_push(
                $result,
                RuleErrorBuilder::message('Potential SQLI: global variable ' . ($varName === "?" ? $varName : "$" . $varName) . ' accessed in ' . $type . '.')
                    ->identifier("security.sqli")
                    ->build()
            );
        } elseif ($node instanceof FuncCall) {
            $result = array_merge($result, $this->isSafeFunction($node, $type));
        } elseif ($node instanceof InterpolatedString) {
            foreach ($node->parts as $part) {
                if (!$part instanceof InterpolatedStringPart) {
                    $result = array_merge($result, $this->isSecure($part, $type));
                }
            }
        } elseif ($node instanceof MethodCall) {
            array_push(
                $result,
                RuleErrorBuilder::message('Potential SQLI: MethodCall ' . $node->name->name . ' in ' . $type . '.')
                    ->identifier("security.sqli")
                    ->build()
            );
        } elseif ($node instanceof StaticCall) {
            array_push(
                $result,
                RuleErrorBuilder::message('Potential SQLI: StaticCall ' . $node->name->name . ' in ' . $type . '.')
                    ->identifier("security.sqli")
                    ->build()
            );
        } elseif ($node instanceof PropertyFetch) {
            /*
             * class User{ public $name;};
             * $user= new User;
             * $user->name=$_GET["name"];
             * $db->query($user->name); => should trigger.
             */
            $varName = $this->getVariableBaseName($node);
            array_push(
                $result,
                RuleErrorBuilder::message('Potential SQLI: unsafe use of the class variable ' . ($varName === "?" ? $varName : "$" . $varName) . '->' . $node->name->name . ' in ' . $type . '.')
                    ->identifier("security.sqli")
                    ->build()
            );
        } elseif ($node instanceof StaticPropertyFetch) {
            /*
             * class User{ public static $table = "users";};
             * User::$table= $_GET["name"];
             * $db->query(User::$table); => should trigger.
             */
            $varName = $this->getStaticPropertyClassName($node);
            array_push(
                $result,
                RuleErrorBuilder::message('Potential SQLI: unsafe use of the class variable ' . ($varName === "?" ? $varName : "$" . $varName) . '::' . $node->name->name . ' in ' . $type . '.')
                    ->identifier("security.sqli")
                    ->build()
            );
        }
        return $result;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $result = [];
        if ($node->name instanceof Identifier && $node->name->name === "query") { // query function call
            foreach ($node->args as $arg) {
                // check if any of the parameters of query (actually there is only one as soon as I know)
                // but anyways, we check all of them
                $result = array_merge($result, $this->isSecure($arg->value, "query"));
            }
        }
        return $result;
    }
}
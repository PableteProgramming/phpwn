<?php

/**
 * Cross-Site Scripting Detection Rule for PHPStan
 * 
 * This rule detects potential XSS vulnerabilities in output statements
 * (echo, print, printf) where user-controlled data may be printed unsanitized.
 * 
 * DETECTION STRATEGY (Conservative / Over-approximate):
 * - Flags ANY variable, superglobal, function call, method call, or property access
 *   that appears in echo, print, or printf output
 * 
 * HANDLED NODE TYPES:
 * - Echo_ (all expressions)
 * - Print_
 * - printf / vprintf (standalone function calls)
 * - Variable           ($name)
 * - ArrayDimFetch      ($_GET['name'], $_POST['data'])
 * - Concat             ("Hello " . $var)
 * - InterpolatedString ("Hello $var")
 * - FuncCall           (getUserName(), trim($_GET['name']))
 * - MethodCall         ($user->getName())
 * - StaticCall         (User::getDefaultName())
 * - PropertyFetch      ($user->name)
 * - StaticPropertyFetch (Config::$siteTitle)
 * 
 * FUNCTION HANDLING:
 * - Safe functions (htmlspecialchars, htmlentities, strip_tags, intval, etc.) -> ignore
 * - Known functions (trim, strtolower, urldecode, etc.) -> check arguments recursively
 * - Unknown functions -> always trigger (conservative)
 * 
 * LIMITATIONS (Why Psalm is needed):
 * - No flow awareness – cannot trace if a variable was sanitized before reaching echo
 * - No taint tracking – cannot confirm if data came from user input
 * - Over-approximates – many false positives expected (e.g., echoing config values)
 * 
 * ROLE IN PIPELINE:
 * - Stage 1: Syntactic pattern matching
 * - Output: All locations where echo/print/printf use dynamic values
 * - Stage 2: Psalm taint analysis filters false positives
 */

namespace $NAMESPACE;

use PhpParser\Node;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Scalar\InterpolatedString;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Stmt\Echo_;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\InterpolatedStringPart;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticPropertyFetch;

/**
 * @implements Rule<Node>
 */
class XSSDetection implements Rule
{
    //functions that are known safe, no trigger
    private $safeFunctions = [
        "htmlspecialchars",
        'htmlentities',
        'strip_tags',
        'filter_var',           // with FILTER_SANITIZE_SPECIAL_CHARS
        'intval',               // numbers can't carry XSS
        'floatval',
        'json_encode',          // JSON output is safe for HTML if properly embedded
        'urlencode',
        'rawurlencode'
    ];

    //functions with known behaviour, check for user controlled arguments
    private $knownFunctions = [
        // String manipulation (preserve taint)
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

        // Decoding (can reintroduce XSS)
        'urldecode',
        'rawurldecode',
        'html_entity_decode',   // Converts &lt; back to < – dangerous!
        'base64_decode',

        // Escaping but NOT for HTML (useless for XSS)
        'addslashes',
        'stripslashes',
        'mysqli_real_escape_string',

        // Hashing
        'md5',
        'sha1',
        'hash',

        // Serialization
        'unserialize',  // dangerous but different vuln class

        // Other
        'str_pad',
        'str_repeat'
    ];

    public function getNodeType(): string
    {
        return Node::class;
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
            RuleErrorBuilder::message('Potential XSS: unsafe function \'' . $node->name->name . '\' called.')
                ->identifier("security.xss")
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
                RuleErrorBuilder::message('Potential XSS: unsafe use of the variable $' . $node->name . ' in ' . $type . '.')
                    ->identifier("security.xss")
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
                RuleErrorBuilder::message('Potential XSS: global variable ' . ($varName === "?" ? $varName : "$" . $varName) . ' accessed in ' . $type . '.')
                    ->identifier("security.xss")
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
                RuleErrorBuilder::message('Potential XSS: MethodCall ' . $node->name->name . ' in ' . $type . '.')
                    ->identifier("security.xss")
                    ->build()
            );
        } elseif ($node instanceof StaticCall) {
            array_push(
                $result,
                RuleErrorBuilder::message('Potential XSS: StaticCall ' . $node->name->name . ' in ' . $type . '.')
                    ->identifier("security.xss")
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
                RuleErrorBuilder::message('Potential XSS: unsafe use of the class variable ' . ($varName === "?" ? $varName : "$" . $varName) . '->' . $node->name->name . ' in ' . $type . '.')
                    ->identifier("security.xss")
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
                RuleErrorBuilder::message('Potential XSS: unsafe use of the class variable ' . ($varName === "?" ? $varName : "$" . $varName) . '::' . $node->name->name . ' in ' . $type . '.')
                    ->identifier("security.xss")
                    ->build()
            );
        }
        return $result;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $result = [];
        // process echo
        if ($node instanceof Echo_) {
            foreach ($node->exprs as $expr) {
                $result = array_merge($result, $this->isSecure($expr, "echo"));
            }
        } elseif ($node instanceof Expression && $node->expr instanceof Print_) { //process print
            $result = array_merge($result, $this->isSecure($node->expr->expr, "print"));
        } elseif ($node instanceof Expression && $node->expr instanceof FuncCall && $node->expr->name->name === "printf") { //process printf
            foreach ($node->expr->args as $arg) {
                $result = array_merge($result, $this->isSecure($arg->value, "printf"));
            }
        }
        return $result;
    }
}
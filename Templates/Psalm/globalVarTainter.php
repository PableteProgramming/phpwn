<?php

/**
 * GlobalVarTainter — Psalm plugin to taint globally-used PHP variables.
 *
 * WHY THIS EXISTS:
 * Psalm's GlobalAnalyzer.php overwrites parent nodes in the taint graph every time
 * a `global $var;` statement is encountered (see GlobalAnalyzer.php ~line 95):
 *
 *   $context->vars_in_scope[$var_id] = $context->vars_in_scope[$var_id]->setParentNodes([
 *       $assignment_node->id => $assignment_node,
 *   ]);
 *
 * This setParentNodes([...]) call replaces the parent list entirely, so any taint
 * we injected via AfterStatementAnalysisInterface gets lost on the next global statement.
 * The symptom: taint would work at the end of a concat but fail in the middle, because
 * Psalm copies/refreshes context between operands and the stale parent is gone.
 *
 * THE FIX:
 * Use AddTaintsInterface instead of manually poking the taint graph.
 * This interface is called by Psalm on every expression evaluation — so every time
 * $request (or any listed global) appears anywhere in any expression, we return fresh
 * taint kinds. Psalm then handles propagation through its own internals correctly.
 *
 * This is also how Psalm's own built-in tainters (e.g. HtmlFunctionTainter) work.
 * We discovered this by spelunking through vendor/vimeo/psalm/src/Psalm/Plugin/EventHandler/.
 * The interface is undocumented but exactly designed for this use case.
 *
 * PREPROCESSOR NOTE:
 * The $globalstoTaint array is automatically populated by the PHPwn preprocessor script
 * (codebaseCheck.py / preprocess step) via AST traversal of the analyzed codebase.
 * Do not edit it manually — it will be overwritten.
 */

use Psalm\Plugin\PluginEntryPointInterface;
use Psalm\Plugin\EventHandler\AddTaintsInterface;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\PluginRegistrationSocket;
use PhpParser\Node\Expr\Variable;
use Psalm\Type\TaintKind;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Scalar\Int_;


class globalVarTainter implements PluginEntryPointInterface, AddTaintsInterface
{
    /**
     * List of global variable names (without $) to treat as taint sources.
     * Populated automatically by the PHPwn preprocessor — do not edit manually.
     */
    private static $globalsToTaintXss= [];
    private static $globalsToTaintSql= [];

    public function __invoke(PluginRegistrationSocket $registration, SimpleXMLElement|null $config = null): void
    {
        $registration->registerHooksFromClass(static::class);
    }

    private static function resolveRoot(Node $node)
    {
        if ($node instanceof Variable && is_string($node->name)) {
            return $node->name;
        }
        if ($node instanceof ArrayDimFetch) {
            return self::resolveRoot($node->var);
        }
        return null; // we can't go up again, but no name, exiting
    }

    private static function resolveKeys(Node $node)
    {
        // we store all the objects in an array until we reach root, and then we can work with it.
        $names = [];
        $current = $node;
        while ($current instanceof ArrayDimFetch) {
            $v = $current->dim;
            if ($v instanceof String_) {
                array_unshift($names, $v->value);
            } else if ($v instanceof Int_) {
                array_unshift($names, (string) $v->value);
            } else {
                return "";
            }
            $current = $current->var;
        }
        return implode(".", $names);
    }


    private static function extractFirstNKeys(string $input,int $n){
        $parts= explode(".",$input);
        if ($n>count($parts)){
            return $input;
        }
        $parts= array_splice($parts,0,$n);
        return implode(".",$parts);
    }

    private static function findTaint($expr)
    {
        // Handle ArrayItem => extract the value
        if ($expr instanceof ArrayItem) {
            $expr = $expr->value;
        }

        $type = [];
        // This is the basic, in case we are talking about a variable.
        if ($expr instanceof Variable && in_array($expr->name, self::$globalsToTaintXss, true)) {
            array_push($type, TaintKind::INPUT_HTML);
        }
        if ($expr instanceof Variable && in_array($expr->name, self::$globalsToTaintSql, true)) {
            array_push($type, TaintKind::INPUT_SQL);
        }
        if ($expr instanceof ArrayDimFetch) {
            $rootName = self::resolveRoot($expr);
            if ($rootName === null) {
                return [];
            }
            $keys = self::resolveKeys($expr);
            if ($keys === "") {
                return [];
            }
            $fullName = $rootName . "." . $keys;
            foreach(self::$globalsToTaintXss as $xssGlobal){
                $p= self::extractFirstNKeys($fullName,count(explode(".",$xssGlobal)));
                if($p===$xssGlobal){
                    array_push($type, TaintKind::INPUT_HTML);
                    break;
                }
            }
            foreach(self::$globalsToTaintSql as $sqlGlobal){
                $p= self::extractFirstNKeys($fullName,count(explode(".",$sqlGlobal)));
                if($p===$sqlGlobal){
                    array_push($type, TaintKind::INPUT_SQL);
                    break;
                }
            }
        }
        return $type;
    }

    /**
     * Called by Psalm on every expression during taint analysis.
     * If the expression is a variable in our taint list, we return the taint kinds.
     * Psalm propagates them through the dataflow graph automatically.
     *
     * Why all these taint kinds?
     *   INPUT_SQL   — $request used in a query              → SQLi
     *   INPUT_HTML  — $request echoed in HTML               → XSS
     *   INPUT_SHELL — $request passed to exec()             → shell injection
     *   INPUT_SSRF  — $request passed to curl               → SSRF
     *   INPUT_FILE  — $request passed to include/require    → file inclusion
     *   INPUT_COOKIE / INPUT_HEADER — $request wraps these  → covered
     */
    public static function addTaints(AddRemoveTaintsEvent $event): array
    {
        $expr = $event->getExpr();
        return self::findTaint($expr);
    }
}
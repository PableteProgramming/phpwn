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

class globalVarTainter implements PluginEntryPointInterface, AddTaintsInterface
{
    /**
     * List of global variable names (without $) to treat as taint sources.
     * Populated automatically by the PHPwn preprocessor — do not edit manually.
     */
    private static $globalstoTaint= [];

    public function __invoke(PluginRegistrationSocket $registration, SimpleXMLElement|null $config = null): void
    {
        $registration->registerHooksFromClass(static::class);
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

        if ($expr instanceof Variable && in_array($expr->name, self::$globalstoTaint, true)) {
            return [
                TaintKind::INPUT_SQL,
                TaintKind::INPUT_HTML,
                TaintKind::INPUT_SHELL,
                TaintKind::INPUT_SSRF,
                TaintKind::INPUT_FILE,
                TaintKind::INPUT_COOKIE,
                TaintKind::INPUT_HEADER,
            ];
        }

        return [];
    }
}
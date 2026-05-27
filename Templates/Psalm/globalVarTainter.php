<?php

/**
 * Template from https://psalm.dev/docs/running_psalm/plugins/authoring_plugins
 * We need to implement PluginEntryPointInterface  for our entry-point class.
 * We will have a single class globalVarTainter for entry-point and plugin logic itself.
 * PluginEntryPointInterface needs __invoke(Psalm\PluginRegistrationSocket $registration, SimpleXMLElement|null $config = null): void
 * and AfterStatementAnalysisInterface needs afterStatementAnalysis(Psalm\Plugin\EventHandler\Event\AfterStatementAnalysisEvent $event): bool|null
 * 
 * Sadly, Psalm's documentation is really bad, so we had to inspect the source code ourselves to understand what to do here.
 * looking at vendor/vimeo/psalm/src/Psalm/FileBasedPluginAdapter.php we can see Psalm's own plugin implementation and reproduce it 
 * 
 * Moreover, we also use phpast.com to see the AST of a global $var; statement.
 */

use Psalm\Plugin\PluginEntryPointInterface;
use Psalm\Plugin\EventHandler\AfterStatementAnalysisInterface;
use Psalm\PluginRegistrationSocket;
use Psalm\Plugin\EventHandler\Event\AfterStatementAnalysisEvent;
use PhpParser\Node\Stmt\Global_;
use PhpParser\Node\Expr\Variable;
use Psalm\Internal\DataFlow\TaintSource;
use Psalm\Internal\DataFlow\DataFlowNode;
use Psalm\CodeLocation;
use Psalm\Type\TaintKind;

class globalVarTainter implements PluginEntryPointInterface, AfterStatementAnalysisInterface{

    private static $globalstoTaint= [];
    function __invoke(PluginRegistrationSocket $registration, SimpleXMLElement|null $config = null): void{
        /*
         * We discover reading source code that we need $registration->registerHooksFromClass(CLASS_NAME);
         * Because the same class also implements AfterStatementAnalysisInterface, we pass static::class as a parameter.
         * We want the class itself to be registered for hook handler
         */
        $registration->registerHooksFromClass(static::class);
    }

    static function afterStatementAnalysis(AfterStatementAnalysisEvent $event): bool|null{
        /**
         * Again, we don't know what to do here.
         * So we look at vendor/vimeo/psalm/src/Psalm/Plugin/EventHandler/Event/AfterStatementAnalysisEvent.php
         * and we see it has the following properties:
         * - getStmt()
         * - getContext()
         * - getStatementsSource()
         * - getCodebase()
         * - getFileReplacements()
         * - setFileReplacements()
         * 
         * Now, we want to check if the statement is a global $var statement.
         * We look at vendor/vimeo/psalm/src/Psalm/Internal/Analyzer/Statements/GlobalAnalyzer.php to understand how they work with global vars
         * and have a kind of template when adding taint to a variable.
         * 
         * Moreover, we identified the issue why our global variables lose taint. At line 95 we can see:
         * $assignment_node = DataFlowNode::getForAssignment(
         *     $var_id,
         *      new CodeLocation($statements_analyzer, $var),
         *  );
         *  $context->vars_in_scope[$var_id] = $context->vars_in_scope[$var_id]->setParentNodes([
         *      $assignment_node->id => $assignment_node,
         *  ]);
         * 
         * Showing that everytime we have a global variable, the variable parent get's overwritten, therefore losing trace and existing taint !
         * Our plugin get's called after every statement, meaning that the context->vars_in_scope[$var] already exists.
         * We then just need to mark it as tainted and add it to the graph so that flowing into sinks gets detected.
         * This are the exact steps:
         * 1) Create a TaintSource — a node that Psalm recognizes as a taint origin
         * 2) Register it in the graph via addSource (start node during traversal) and addNode (normal node during traversal)— so connectSinksAndSources() picks it up when traversing, 
         * 3) Add a forward edge from our TaintSource to the node GlobalAnalyzer just created — this is the missing link in the chain
         *      => We want the link to work, and therefore, we need to do it exactly like GlobalAnalyzer.php:95, so that every id etc matches. 
         * 4) Add it as a parent node on the Union type — for expression-level taint tracking
         *   => just like in GlobalAnalyzer.php:99
         * 
         * For TaintSource, we looked at vendor/vimeo/psalm/src/Psalm/Internal/DataFlow/TaintSource.php and for 
         * CodeLocation at vendor/vimeo/psalm/src/Psalm/CodeLocation.php
         * 
         * Why do we put all of those taints in there? 
         * INPUT_SQL — $request['get']['id'] used in a query → SQL injection
         * INPUT_HTML — $request['get']['name'] echoed in HTML → XSS
         * INPUT_SHELL — $request['get']['file'] passed to exec() → shell injection
         * INPUT_SSRF — $request['get']['url'] passed to curl → SSRF
         * INPUT_FILE — $request['get']['path'] passed to include → file inclusion
         * INPUT_COOKIE — covered by $request since it includes cookie data
         * INPUT_HEADER — same
         * 
         * These types are defined in vendor/vimeo/psalm/src/Psalm/Type/TaintKind.php
         * 
         * In vendor/vimeo/psalm/src/Psalm/Codebase.php, we can see that we have access to the TaintFlowGraph
         * 
         * The path Types possible are:
         * ['variable-use',
         *  'closure-use',
         *  'global-use',
         *  'use-inside-instance-property',
         *  'use-inside-static-property',
         *  'use-inside-call',
         *  'use-inside-conditional',
         *  'use-inside-isset',
         *  'arg',
         *  'comparison']
         * 
         * We don't know what each type means, but the global-use sound pretty good for our use case xD
         */

        $stmt= $event->getStmt();
        $context= $event->getContext();

        if($stmt instanceof Global_){
            // we are in a global statement
            foreach($stmt->vars as $var){
                if($var instanceof Variable){
                    // it is a global $var statement
                    if (in_array($var->name,self::$globalstoTaint)){
                        // we want to taint this variable !
                        $varId= '$'.$var->name;

                        if(isset($context->vars_in_scope[$varId])){
                            // this is a virtual node that just represents the start of a taint track
                            $taintSource= new TaintSource(
                                $varId.'-global-taint', // we name it how we want, it has to be unique
                                $varId, // this is the label, $varId so that the user can read it properly.
                                new CodeLocation($event->getStatementsSource(), $event->getStmt()), // this is the codeLocation object, needed internally by Psalm
                                null, //don't know what that does, can be null, so set it to null
                                [
                                    TaintKind::INPUT_SQL,
                                    TaintKind::INPUT_HTML,
                                    TaintKind::INPUT_SHELL,
                                    TaintKind::INPUT_SSRF,
                                    TaintKind::INPUT_FILE,
                                    TaintKind::INPUT_COOKIE,
                                    TaintKind::INPUT_HEADER,

                                ] // this are the taints, we put all of them. See explanantion above
                            );

                            $taintFlowGraph= $event->getCodebase()->taint_flow_graph;
                            if(isset($taintFlowGraph)){
                                //to avoid runtime exception
                                $taintFlowGraph->addSource($taintSource);
                                $taintFlowGraph->addNode($taintSource);

                                // this represent our actual $var
                                $assignment_node = DataFlowNode::getForAssignment(
                                    $varId,
                                    new CodeLocation($event->getStatementsSource(), $var)
                                );
                                //now we add this node to the graph
                                $taintFlowGraph->addNode($assignment_node);

                                //now we link the taint source to the $var node
                                $taintFlowGraph->addPath($taintSource,$assignment_node,'global-use');
                                
                                //Finally, we set the parent of the $var's type in the context 
                                $context->vars_in_scope[$varId] = $context->vars_in_scope[$varId]->setParentNodes([
                                    $assignment_node->id => $assignment_node,
                                ]);
                            }

                        }
                        //else, the Global Analyzer didn't create the entry, so we cannot work with it...skip
                    }
                }
            }
        }
        return null;
    }
}
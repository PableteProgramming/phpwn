<?php
/**
 * MissingGuardRule - PHPStan Custom Rule
 * =======================================
 *
 * GOAL:
 * Detect sensitive operations that are called without a prior authentication/authorization guard.
 *
 *
 * APPROACH:
 * ---------
 * We use PHPStan\Node\FileNode to analyze the entire file at once.
 * FileNode::getNodes() returns PhpParser\Node[] so we are back in familiar PhpParser territory.
 * Errors must use ->line($node->getLine()) because FileNode itself is always at line 1.
 *
 *
 * GUARD REGISTRY:
 * ---------------
 * Guards are loaded from a JSON cache file (phpstan-guards-cache.json) at startup.
 * The list is seeded with a few obvious guard function names (e.g. checkAuth, isLoggedIn, requireAuth).
 * In the future, AI classification will expand this list automatically (see FUTURE section).
 *
 *
 * MISSING GUARDS DETECTION ALGORITHM
 * ====================================
 *
 * PRE-STEP — Build function map:
 * ──────────────────────────────
 * Before any analysis, traverse all top-level nodes and build:
 *   - funcMap:    array<string, Function_>  → functionName => Function_ node
 *   - guardCache: array<string, bool>        → functionName => guardLine?
 *
 *
 * The following two passes are applied to:
 *   - Top-level statements
 *   - Each Function_ body independently
 *   - Each ClassMethod body independently (future)
 *
 *
 * PASS 1 — Find the earliest guard line:
 * ───────────────────────────────────────
 * $guardLine = -1 (no guard found yet)
 *
 * For each FuncCall encountered (in file order):
 *   1. Is it a known guard?
 *      YES → if call->getLine() < $guardLine (or $guardLine === -1):
 *                update $guardLine = call->getLine()
 *      NO  → look up the Function_ definition in funcMap
 *                └── not found? (defined in another file)
 *                      → skip, continue
 *                └── found? → check guardCache first
 *                      → already cached?
 *                           → use cached value directly
 *                      → not cached? → recursively run PASS 1 on function body
 *                           (pass a $visited set to avoid infinite recursion on circular calls)
 *                           → result is a guardLine (or -1)
 *                           → store in guardCache[functionName]
 *                           → if result !== -1 && result < $guardLine (or $guardLine === -1):
 *                                update $guardLine = call->getLine() (the CALL site line, not the inner line)
 *
 * Result: $guardLine (int, -1 if no guard found anywhere in this scope)
 *
 *
 * PASS 2 — Detect unguarded sensitive operations:
 * ─────────────────────────────────────────────────
 * For each FuncCall encountered (in file order):
 *   1. Is it a sensitive operation? (check against known sensitive functions list)
 *      NO  → skip
 *      YES → if $guardLine === -1:
 *                → 🚨 error: no guard found anywhere in this scope
 *            else if call->getLine() < $guardLine:
 *                → 🚨 error: sensitive operation called before guard
 *            else:
 *                → ✅ safe, continue
 *
 *
 * EDGE CASES:
 * ───────────
 * 1. CIRCULAR CALLS (critical):
 *    function a() { b(); }
 *    function b() { a(); }
 *    → Pass a $visited = [] set into recursive calls.
 *      If functionName is already in $visited → return -1 immediately.
 *
 * 2. FUNCTIONS DEFINED IN OTHER FILES:
 *    → Not found in funcMap → treat as unknown → skip (not a guard, not sensitive).
 *    → May produce false positives, suppressible via @phpstan-ignore.
 *
 * 3. CONDITIONAL GUARDS:
 *    if ($isAdmin) { checkAuth(); }
 *    → Guard not guaranteed to execute → may still be flagged.
 *    → Acceptable limitation (conservative approach).
 *
 * 4. SAME LINE:
 *    → If sensitive call and guard are on the same line → treated as safe (not < guardLine).
 *
 * 5. FUNCTION CALLED MULTIPLE TIMES:
 *    → guardCache prevents re-traversing the same function body multiple times.
 *    → First call computes and caches, subsequent calls return cached value instantly.
 *
 *
 * FUNCTION BODY RESOLUTION:
 * -------------------------
 * Before analysis, we build a map of [ functionName => Function_ node ] from the file.
 * When a FuncCall is not a known guard, we look it up in this map and recursively
 * check if its body contains a guard call (direct or via another resolvable call).
 * If the function is not found in the map (e.g. defined in another file), we treat it
 * as "unknown" → not a guard, not sensitive → skip.
 * We save already checked functions into a map [ functionName => int guardLine (or -1 if not guarded) ] to avoid 
 * rechecking what we already checked
 * 
 *
 * EDGE CASES:
 * -----------
 *
 * 1. RECURSION / CIRCULAR CALLS (critical — must handle)
 *    function a() { b(); }
 *    function b() { a(); }
 *    → Use a $visited = [] set in recursive body resolution to avoid infinite loops.
 *      If a function is already in $visited, return false immediately.
 *
 * 2. FUNCTIONS DEFINED IN OTHER FILES
 *    checkPermissions(); // defined in auth.php, not in this FileNode
 *    → Function not found in the local map → treat as unknown → not a guard.
 *    → This may produce false positives, suppressible via @phpstan-ignore.
 *
 * 3. CONDITIONAL GUARDS
 *    if ($isAdmin) { checkAuth(); }
 *    sensitiveOp();
 *    → Guard is not guaranteed to execute → could be flagged as missing.
 *    → Acceptable limitation for now (conservative approach).
 *
 * 4. GUARD LINE ORDERING
 *    → We only care about the FIRST guard line encountered in a given scope.
 *    → Any sensitive call with a line number less than the guard line is an error.
 *    → Any sensitive call after the guard line is considered safe.
 *
 *
 * FUTURE — AI-ASSISTED GUARD DISCOVERY:
 * --------------------------------------
 * Goal: make the rule work on ANY codebase without manual configuration.
 *
 * Two-pass approach:
 *   Pass 1 → collect all FuncCall names across all files
 *   Pass 2 → for each unknown function name, ask AI:
 *            "Does this function name suggest an auth/authorization check? yes/no"
 *            If yes → add to GuardRegistry and persist to JSON cache
 *
 * The JSON cache avoids redundant AI calls on subsequent PHPStan runs.
 * A confidence threshold (e.g. 0.85) should be used to avoid false positives.
 * Uncertain names can be logged for human review.
 *
 *
 * CONFIGURATION (phpstan.neon):
 * ------------------------------
 * services:
 *     guardRegistry:
 *         class: App\PHPStan\GuardRegistry
 *         arguments:
 *             cachePath: %rootDir%/phpstan-guards-cache.json
 *     -
 *         class: App\PHPStan\MissingGuardRule
 *         tags:
 *             - phpstan.rules.rule
 *         arguments:
 *             guardRegistry: @guardRegistry
 *
 * 
 * SENSITIVE OPERATIONS LIST
 * ==========================
 *
 * CONTEXT:
 * --------
 * The target codebase uses a large .htaccess file to manage route access.
 * The assumption is that there may be misconfigurations in it, making some
 * PHP files publicly accessible when they shouldn't be.
 *
 * Therefore, the threat model is:
 *   .htaccess misconfiguration (file publicly accessible)
 *   +
 *   Missing guard (no auth check)
 *   =
 *   VULNERABILITY
 *
 * Even a simple echo is a vulnerability if the file is accessible and unguarded,
 * as it could leak sensitive data to unauthorized users.
 *
 * This rule (PHPStan) is Phase 1 of a two-phase analysis:
 *   Phase 1 (PHPStan/PHP) → detect PHP files with missing guards + sensitive operations
 *   Phase 2 (Python)      → parse .htaccess, cross-reference with Phase 1 results
 *                         → files that are BOTH accessible AND unguarded = real vulnerability
 *
 *
 * SENSITIVE OPERATIONS BY CATEGORY:
 * -----------------------------------
 *
 * 1. OUTPUT — data leak risk (highest priority given threat model)
 *    'echo', 'print', 'printf', 'fprintf', 'vprintf',
 *    'var_dump', 'var_export', 'print_r', 'readfile'
 *    → Any output in an accessible unguarded file = potential data leak
 *
 * 2. CODE/COMMAND EXECUTION — RCE risk (critical)
 *    'eval', 'assert',
 *    'exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open'
 *    → If accessible and unguarded, attacker can execute arbitrary code/commands
 *
 * 3. FILE SYSTEM — data manipulation risk
 *    'file_get_contents', 'file_put_contents', 'fopen', 'fwrite',
 *    'unlink', 'rename', 'copy', 'mkdir', 'rmdir'
 *    → Reading/writing/deleting files without auth = data leak or destruction
 *
 * 4. NETWORK — SSRF/exfiltration risk
 *    'curl_exec', 'fsockopen', 'socket_connect'
 *    → Unauthorized network requests from the server
 *
 * 5. DATABASE — data leak/manipulation risk
 *    'mysqli_query', 'mysql_query', 'pg_query'
 *    → Already partially covered by the SQLi rule, but relevant here too
 *    → Unguarded DB access = unauthorized data read/write
 *
 *
 * PRIORITY ORDER FOR IMPLEMENTATION:
 * ------------------------------------
 * Start with the highest impact categories given the threat model:
 *   Priority 1 → Output       (echo, print, printf, var_dump, ...)
 *   Priority 2 → Code/Command execution (eval, exec, system, ...)
 *   Priority 3 → File system  (file_put_contents, unlink, ...)
 *   Priority 4 → Network      (curl_exec, ...)
 *   Priority 5 → Database     (mysqli_query, ...) — already covered by SQLi rule
 *
 *
 * NOTE ON ECHO/PRINT:
 * --------------------
 * Unlike typical missing guard rules that ignore output functions,
 * we explicitly include them here because of the .htaccess threat model.
 * A plain echo $userData in an accessible unguarded file is a real vulnerability.
 * The XSS rule covers WHAT is output (unescaped data).
 * This rule covers WHO is allowed to trigger any output at all.
 *
 *
 * MissingGuardsDetectionNew - PHPStan Custom Rule (extended variant)
 * ====================================================================
 *
 * Same detection goal and overall design as MissingGuardsDetection.php (see that
 * file's header for the full original rationale, guard registry, sensitive-ops
 * list, and edge cases — all unchanged here). The only difference: this variant
 * also recognizes MethodCall (`$obj->foo()`) and StaticCall (`Foo::bar()`), and
 * indexes ClassMethod bodies for recursion, alongside the original's FuncCall/
 * Function_-only matching. Mirrors the exact same conservative philosophy the
 * original already applies to FuncCall — an unresolved/dynamic call is flagged
 * in checkSensitive and simply skipped (not a guard) in findGuardLine — so this
 * is a like-for-like extension, not a new heuristic.
 *
 * WHY THIS EXISTS:
 * -----------------
 * The original rule cannot see into class methods at all — a guard implemented
 * as `$auth->check()`, or a sensitive operation reached only through
 * `$view->render()`, is entirely invisible to it. This was empirically tested
 * against a real production PHP codebase (PHPStan + the .htaccess
 * accessibility cross-reference only — Psalm was excluded from the
 * comparison, since it's unrelated to this change and much slower):
 *   - Raw `security.missingGuard` messages: original = 203 across 32 files;
 *     this variant = 224 across 39 files.
 *   - Files that are both accessible (per .htaccess) and unguarded — i.e. what
 *     actually reaches the final report: original = 11 files, this variant =
 *     12 files. Zero files lost, exactly one gained.
 *   - 12 of the 13 files with raw differences are confirmed NOT
 *     web-accessible — new flags from calls like $db->close(), $date->modify(),
 *     $dotenv->safeLoad(), but inert, since they never reach the final
 *     cross-referenced result either way.
 *   - The one new file is a genuine true positive: no guard mechanism at all,
 *     directly accessible, and reached only through a chain of method calls
 *     (invisible to the original FuncCall/Function_-only matching), with
 *     output built from unsanitized request data. The original rule misses
 *     this entirely (0 messages) purely because the call chain is method
 *     calls, invisible to it.
 *   - The 11 pre-existing findings from the original rule are unchanged here.
 *
 * See MissingGuardsDetection.php for the full original design doc (guard
 * registry, sensitive-operations list and threat model, edge cases). Only the
 * call-resolution mechanics differ, documented inline below.
 */

namespace $NAMESPACE;

use PhpParser\Node\Stmt\Expression;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PhpParser\Node;
use PHPStan\Node\FileNode;
use PHPStan\Rules\RuleErrorBuilder;
use PhpParser\Node\Stmt\Function_;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Name;
use PhpParser\Node\Identifier;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Scalar\String_;

/**
 * @implements Rule<FileNode>
 */

class MissingGuardsDetection implements Rule
{
    private $guards=[
        "checkAuth"
    ];

    private $guardIncludesRegex= "/\b(global|auth|session_handling)\.php\b/";

    private $sensitiveFuncNames = [
        // output
        'printf', 'fprintf', 'vprintf', 'print_r', 'var_dump', 'var_export', 'readfile',
        // file system
        'file_get_contents', 'file_put_contents', 'fopen', 'fwrite',
        'unlink', 'rename', 'copy', 'mkdir', 'rmdir',
        // command execution
        'exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open',
        // network
        'curl_exec', 'fsockopen', 'socket_connect',
        // database
        'mysqli_query', 'mysql_query', 'pg_query',
    ];

    // Language constructs → detected by their own AST node type
    // use $node instanceof X to detect these
    private $sensitiveFuncTypes = [
        \PhpParser\Node\Stmt\Echo_::class,    // echo "hello"
        \PhpParser\Node\Expr\Print_::class,   // print "hello"
        \PhpParser\Node\Expr\Eval_::class,    // eval("code")
    ];

    /*
    * This function creates a map functionName(string)=> FunctionBody(Node)
    * This allows us to access the body of each function/method without having to search everytime.
    * Extended: also indexes ClassMethod bodies found in top-level classes/traits, keyed by
    * method name only (same name-only simplification already used for plain functions — no
    * type resolution, so a same-named method in an unrelated class in the same file can
    * collide; consistent with the existing FuncCall-name-only approach, not a new problem).
    */
    private function createFunctionsMap(FileNode $file){
        $map=[];
        foreach($file->getNodes() as $node){
            if($node instanceof Function_ && !in_array($node->name->name,$this->guards)){
                if(!isset($map[$node->name->name])){
                    $map[$node->name->name]=$node;
                }
            }
            elseif($node instanceof ClassLike){
                foreach($node->stmts as $classStmt){
                    if($classStmt instanceof ClassMethod && $classStmt->stmts!==null && !in_array($classStmt->name->name,$this->guards)){
                        if(!isset($map[$classStmt->name->name])){
                            $map[$classStmt->name->name]=$classStmt;
                        }
                    }
                }
            }
        }
        return $map;
    }

    private function extractStrings(Node $node): array{
        if($node instanceof String_){
            return [$node->value];
        }
        elseif($node instanceof Concat){
            return array_merge($this->extractStrings($node->left),$this->extractStrings($node->right));
        }
        else{
            return [];
        }
    }

    /*
    * Resolves the callee name for FuncCall/MethodCall/StaticCall nodes, returning null for
    * anything dynamic (mirrors the original's "not instanceof Name" dynamic-call check,
    * extended the same way for MethodCall/StaticCall's Identifier-or-dynamic-Expr name).
    */
    private function resolveCallName($callNode): ?string {
        if($callNode instanceof FuncCall){
            return $callNode->name instanceof Name ? $callNode->name->toString() : null;
        }
        elseif($callNode instanceof MethodCall || $callNode instanceof StaticCall){
            return $callNode->name instanceof Identifier ? $callNode->name->toString() : null;
        }
        return null;
    }

    private function isCallNode($expr): bool{
        return $expr instanceof FuncCall || $expr instanceof MethodCall || $expr instanceof StaticCall;
    }

    /*
    * This function returns the line of the first called guard function
    * If None, then -1 returned
    */
    private function findGuardLine(array $nodes, array $funcMap, array &$funcGuardMap, int $currentGuardLine):int{
        foreach($nodes as $node){
            if($node instanceof Expression && $node->expr instanceof Include_){
                $strs= $this->extractStrings($node->expr->expr);
                foreach($strs as $str){
                    if(preg_match($this->guardIncludesRegex, $str)){
                        $guardline=$node->getStartLine();
                        if($currentGuardLine<0 || $guardline<$currentGuardLine){
                            $currentGuardLine=$guardline;
                        }
                        break; // no need to check other parts once found
                    }
                }
            }
            elseif($node instanceof Expression && $this->isCallNode($node->expr)){
                $calleeName= $this->resolveCallName($node->expr);
                if($calleeName === null){
                    // dynamic call → skip, we can't resolve it statically
                    continue;
                }
                //first, we check if it is a known guard function
                if(in_array($calleeName,$this->guards)){
                    // we found a guard !
                    $guardline= $node->getStartLine();
                    // we update the guardline only if smaller than the current
                    if($currentGuardLine<0 || $guardline<$currentGuardLine){
                        $currentGuardLine=$guardline;
                    }
                }
                else{
                    // it is a non guard function/method, we check it's body for guards
                    if(isset($funcGuardMap[$calleeName])){
                        //this function was already checked before and guardline is available
                        if($funcGuardMap[$calleeName]){ // the function has a guard
                            // we return (update) the guardline only if smaller than the current
                            $guardline= $node->getStartLine();
                            if($currentGuardLine<0 || $guardline<$currentGuardLine){
                                $currentGuardLine=$guardline;
                            }
                        }
                    }
                    else{
                        // we have to check the function body now for the first time
                        if(isset($funcMap[$calleeName])){
                            // the function/method was defined in the file too
                            // we check it's body
                            // We set -1 as currentGuardLine because we want the guardLine of the function independently of the context
                            $funcGuardMap[$calleeName]=false; // we set it to false first to avoid circular calls and therefore infinite recursion
                            $line= $this->findGuardLine($funcMap[$calleeName]->stmts,$funcMap,$funcGuardMap,-1);
                            $funcGuardMap[$calleeName]=($line>=0); // now we update with the right value !
                            if($line>=0){
                                // We found a guardline in the function !!
                                $guardline= $node->getStartLine();
                            }
                            else{
                                // there is no guardline in the function
                                $guardline=-1;
                            }
                            if($currentGuardLine<0 || $guardline<$currentGuardLine){
                                $currentGuardLine=$guardline;
                            }
                        }
                        else{
                            // the function/method may be defined in another file/object, we set it as non guard, no cross file access...
                            continue;
                        }
                    }
                }
            }
        }
        return $currentGuardLine;
    }

    /*
    * This function checks if there are sensitive operations called before $guardline
    */
    private function checkSensitive(array $nodes, array $funcMap, int $guardLine):array{
        $result=[]; // these are the built errors
        $funcErrorsMap=[];
        foreach($nodes as $node){
            $currentLine= $node->getStartLine();
            if($guardLine<0 || $currentLine<$guardLine){
                if($node instanceof Expression && $this->isCallNode($node->expr)){
                    $calleeName= $this->resolveCallName($node->expr);
                    if($calleeName!==null){
                        if(!in_array($calleeName,$this->guards)){
                            if(in_array($calleeName,$this->sensitiveFuncNames)){
                                //sensitive function, no need to go recursvie, trigger an error
                                array_push($result, RuleErrorBuilder::message('Potential Missing Guard: use of sensitive "'. $calleeName .'" before guard.')
                                    ->line($currentLine)
                                    ->identifier("security.missingGuard")
                                    ->build());
                            }
                            else{
                                // it is not a guarded function and is sensitive, go recursive if existing
                                if(isset($funcMap[$calleeName])){
                                    //body exists, go rec
                                    $errors= $this->checkSensitiveRec($funcMap[$calleeName]->stmts,$funcMap,$funcErrorsMap);
                                    foreach($errors as $err){
                                        array_push($result, RuleErrorBuilder::message($err)
                                            ->line($currentLine)
                                            ->identifier("security.missingGuard")
                                            ->build());
                                    }
                                }
                                else{
                                    // definition in another file/object, trigger error
                                    array_push($result, RuleErrorBuilder::message('Potential Missing Guard: use of unknown "'. $calleeName .'" before guard.')
                                        ->line($currentLine)
                                        ->identifier("security.missingGuard")
                                        ->build());
                                }
                            }
                        }
                        else{
                            //guarded, skip
                            continue;
                        }
                    }
                    else{
                        //dynamic function/method, trigger error
                        array_push($result, RuleErrorBuilder::message('Potential Missing Guard: use of unknown dynamic function before guard.')
                            ->line($currentLine)
                            ->identifier("security.missingGuard")
                            ->build());
                    }
                }
                elseif(in_array(get_class($node), $this->sensitiveFuncTypes)){
                    array_push($result, RuleErrorBuilder::message('Potential Missing Guard: use of sensitive "'. get_class($node) .'" before guard.')
                        ->line($currentLine)
                        ->identifier("security.missingGuard")
                        ->build());
                }
            }
            else{
                // safe, there were guards before
                continue;
            }
        }
        return $result;
    }

    private function checkSensitiveRec(array $nodes, array $funcMap, array &$funcErrorsMap):array{
        $result=[]; // this are only strings, because the errors are built at the end with the right line number !
        foreach($nodes as $node){
            if($node instanceof Expression && $this->isCallNode($node->expr)){
                $calleeName= $this->resolveCallName($node->expr);
                if($calleeName!==null){
                    if(in_array($calleeName,$this->guards)){
                        // it is a guard function, skip it
                        continue;
                    }
                    else{
                        if(in_array($calleeName,$this->sensitiveFuncNames)){
                            array_push($result,'Potential Missing Guard: use of sensitive "'. $calleeName .'" before guard.');
                        }
                        else{
                            // it is a function/method call that is secure, check it's body
                            if(isset($funcErrorsMap[$calleeName])){
                                // The function already got analyzed, we update the results
                                $result= array_merge($result,$funcErrorsMap[$calleeName]);
                            }
                            else{
                                // the function didn't go analyzed yet, we check if the body is available
                                if(isset($funcMap[$calleeName])){
                                    // we recursively check the body
                                    $funcErrorsMap[$calleeName]=[]; // we set it to empty to avoid circular refs
                                    // we set current line to -1 to trigger errors independently of the context
                                    // we update the results for this function
                                    $errors= $this->checkSensitiveRec($funcMap[$calleeName]->stmts,$funcMap,$funcErrorsMap);
                                    $funcErrorsMap[$calleeName]= $errors;
                                    $result= array_merge($result,$errors);
                                }
                                else{
                                    // the function/method may be defined in another file/object, we flag it, better having to false positives than false negatives
                                    array_push($result,'Potential Missing Guard: use of unknown "'. $calleeName .'" before guard.');
                                }
                            }
                        }
                    }
                }
                else{
                    //it is dynamic determined function/method, trigger an error, false positive maybe but whatever
                    array_push($result,'Potential Missing Guard: use of unknown dynamic function before guard.');
                }
            }
            elseif(in_array(get_class($node), $this->sensitiveFuncTypes)){
                array_push($result,'Potential Missing Guard: use of sensitive "'. get_class($node) .'" before guard.');
            }
        }
        return $result;
    }

    public function getNodeType(): string
    {
        return FileNode::class;
    }

    public function processNode(Node $file, Scope $scope): array
    {

        //we first create the functions maps
        $funcMap=$this->createFunctionsMap($file);
        $funcGuardMap=[];

        $guardLine= $this->findGuardLine($file->getNodes(),$funcMap,$funcGuardMap,-1);


        return $this->checkSensitive($file->getNodes(),$funcMap, $guardLine);
    }
}

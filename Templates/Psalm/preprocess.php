<?php

/**
 * This are the variables you may edit to adapt it to your codebase
 * - $skipDirs contains the directories that are not going to be checked by the preprocessing step, for example vendor files or migrations
 * - $safePatterns are the patterns for safe global variables
 * - $inputPatterns are the patterns for global variables that may contain use input and have to be tainted
 * Run this script with --globals to get the list of all global variables, and adapt both lists depending on it 
 */

$skipDirs = ['vendor', 'cron', '.phpwn', 'preprocess.php', 'psalm', 'phpstan'];
$safePatterns = [];
$xssPatterns = [];
$sqlPatterns = [];
$psalmPluginsDir = "psalm/plugins/globalVarTainter.php";
$arrayDepth = 1;

use PhpParser\NodeVisitorAbstract;
use PhpParser\Node;
use PhpParser\Node\Stmt\Global_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Scalar\Int_;
use PhpParser\Node\Scalar\Float_;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Name;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\ArrayDimFetch;

require_once('vendor/autoload.php');

/**
 * This function returns all the files with extension $extension 
 * in the directory $dir and subdirectories skipping entries containing $skipDirs
 */
function getAllFiles(string $dir, array $skipDirs, string $extension): array
{
    $files = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS));

    foreach ($iterator as $file) {
        if ($file->getExtension() === $extension) {
            $path = $file->getPathname();
            $ok = true;
            foreach ($skipDirs as $skip) {
                if (str_contains($path, DIRECTORY_SEPARATOR . $skip . DIRECTORY_SEPARATOR)) {
                    $ok = false;
                    break;
                }
            }
            if ($ok) {
                array_push($files, $path);
            }
        }
    }
    return $files;
}

/**
 * This is the flow of the nikic/php-parser is:
 * PHP code (string)
 *      → Parser → AST (tree of Node objects)
 *          → NodeTraverser (walks every node)
 *              → NodeVisitor::enterNode() (your code, called on each node)
 */

class GlobalVarVisitor extends NodeVisitorAbstract
{
    public $globalVars = [];
    public $assignments = [];

    private $onlyList = false;

    public $typeMap = [
        Array_::class => "array",
        String_::class => "string",
        Int_::class => "int",
        Float_::class => "float",
        ConstFetch::class => "bool",
        InterpolatedString::class => "string",
        Concat::class => "string"
    ];

    public function __construct(bool $l = false)
    {
        $this->onlyList = $l;
    }

    public function enterNode(Node $node)
    {
        if ($node instanceof Global_) {
            // we have a global statement
            foreach ($node->vars as $var) {
                if ($var instanceof Variable) {
                    $this->globalVars[$var->name] = true;
                }
            }
        } else if (!$this->onlyList && $node instanceof Assign) {
            $var = $node->var;
            $expr = $node->expr;

            if ($var instanceof Variable) {
                if ($expr instanceof New_) {
                    if ($expr->class instanceof Name) {
                        $exprType = implode('\\', $expr->class->getParts());
                    } else {
                        $exprType = "mixed";
                    }
                } else {
                    $exprType = $this->typeMap[get_class($expr)] ?? "mixed";
                }
                // we use an array instead of variable, and we at the end clean it up to get the more precise type def
                $this->assignments[$var->name][] = $exprType;
            }
        }
    }
}

class ArrayElemVisitor extends NodeVisitorAbstract
{
    public $globalVars = [];
    public $existingVars = [];
    public $assignments = [];

    private $onlyList = false;

    private int $depth;

    public $typeMap = [
        Array_::class => "array",
        String_::class => "string",
        Int_::class => "int",
        Float_::class => "float",
        ConstFetch::class => "bool",
        InterpolatedString::class => "string",
        Concat::class => "string"
    ];

    public function __construct($existingVars, bool $l = false, int $depth = 1)
    {
        $this->onlyList = $l;
        $this->existingVars = $existingVars;
        $this->depth = $depth;
    }

    private function resolveRoot(Node $node)
    {
        if ($node instanceof Variable && is_string($node->name)) {
            return $node->name;
        }
        if ($node instanceof ArrayDimFetch) {
            return $this->resolveRoot($node->var);
        }
        return null; // we can't go up again, but no name, exiting
    }

    private function resolveKeyAtDepth(Node $node, int $depth)
    {
        // we store all the objects in an array until we reach root, and then we can work with it.
        $elems = [];
        $current = $node;
        while ($current instanceof ArrayDimFetch) {
            array_push($elems, $current);
            $current = $current->var;
        }
        $totalDepth = count($elems);

        // check if it is exactly the depth we want if not, skip, probably a node already visited. etnernode visits Every node ! 
        if ($totalDepth !== $depth) {
            return [];
        }
        $currentDepth = $depth;
        // we now have the depth we wanna extract, we go from there and store the names until we reach the depth wanted or a dynamic key
        $output = [];
        while ($currentDepth >= 1) {
            $elem = $elems[$currentDepth - 1];
            $value = $elem->dim;
            if ($value instanceof String_) {
                array_push($output, $value->value);
            } else if ($value instanceof Int_) {
                array_push($output, (string) $value->value);
            } else {
                return [];
            }
            $currentDepth--;
        }
        return $output;
    }

    public function enterNode(Node $node)
    {
        if ($node instanceof ArrayDimFetch) {
            $parentName = $this->resolveRoot($node);
            if ($parentName !== null && isset($this->existingVars[$parentName])) {
                // we have a array access of a global variable to track.
                $path = $this->resolveKeyAtDepth($node, $this->depth);
                if (!empty($path)) {
                    // we prepend the var name
                    array_unshift($path, $parentName);
                    $this->globalVars[implode('.', $path)] = $path;
                }
            }
        } else if (!$this->onlyList && $node instanceof Assign) {
            $var = $node->var;
            $expr = $node->expr;

            if ($var instanceof ArrayDimFetch) {
                if ($expr instanceof New_) {
                    if ($expr->class instanceof Name) {
                        $exprType = implode('\\', $expr->class->getParts());
                    } else {
                        $exprType = "mixed";
                    }
                } else {
                    $exprType = $this->typeMap[get_class($expr)] ?? "mixed";
                }

                $parentName = $this->resolveRoot($var);
                if ($parentName !== null) {
                    $path = $this->resolveKeyAtDepth($var, $this->depth);
                    if (!empty($path)) {
                        // we prepend the var name
                        array_unshift($path, $parentName);
                        // we use an array instead of variable, and we at the end clean it up to get the more precise type def
                        $this->assignments[implode('.', $path)][] = $exprType;
                    }
                }
            }
        }
    }
}

/**
 * This class updates the psalm.xml file depending on the given global variables (safe variables, not tainted)
 */
class PsalmXMLConfig
{
    private $filePath;

    public function __construct(string $path)
    {
        $this->filePath = $path;
    }

    private function dotPathToPsalmVar(string $dotPath): string
    {
        $parts = explode('.', $dotPath);
        $name = array_shift($parts);
        foreach ($parts as $part) {
            $name .= "['" . $part . "']";
        }
        return $name;
    }

    public function update(array $globalVars): bool
    {
        if(count($globalVars)<=0){
            return true;
        }
        try {
            $xml = new DOMDocument("1.0");
            $xml->preserveWhiteSpace = false;
            $xml->formatOutput = true;
            if ($xml->load($this->filePath)) {
                $globalsTag = $xml->getElementsByTagName("globals")->item(0);
                if ($globalsTag === null) {
                    // not there yet, we create it
                    $globalsTag = $xml->createElement("globals");
                    $xml->documentElement->appendChild($globalsTag);
                } else {
                    //already there, so we clean it
                    while ($globalsTag->firstChild) {
                        $globalsTag->removeChild($globalsTag->firstChild);
                    }
                }

                foreach ($globalVars as $var => $type) {
                    // we add the variable and it's type to teh psalm.xml
                    $varNode = $xml->createElement("var");
                    $varNode->setAttribute("name", $this->dotPathToPsalmVar($var));
                    $varNode->setAttribute("type", $type);
                    $globalsTag->appendChild($varNode);
                }

                if (!$xml->save($this->filePath)) {
                    echo "[!] Could not save " . $this->filePath . "\n";
                    return false;
                }
                ;
                return true;

            } else {
                echo "[!] Error loading xml file " . $this->filePath . "\n";
                return false;
            }
        } catch (Exception $e) {
            echo "[!] XML error: " . $e->getMessage() . "\n";
            return false;
        }
    }
}

function modifyPlugin(string $filename, array $taintedGlobalsXss, array $taintedGlobalsSql): bool
{
    $taintedListXss = "";
    $taintedListSql = "";
    if(count($taintedGlobalsXss)>0){
        $taintedListXss = '"' . implode('", "', $taintedGlobalsXss) . '"';
    }
    if(count($taintedGlobalsSql)>0){
        $taintedListSql = '"' . implode('", "', $taintedGlobalsSql) . '"';
    }
    $pluginCode = file_get_contents($filename);
    if ($pluginCode !== false) {
        $pluginCode = preg_replace(
            '/private static \$globalsToTaintXss\s*=.*?;/s',
            'private static $globalsToTaintXss= [' . $taintedListXss . '];',
            $pluginCode
        );

        if ($pluginCode === null) {
            echo "[!] An error ocurred while trying to replace the file content\n";
            return false;
        } else {
            $pluginCode = preg_replace(
                '/private static \$globalsToTaintSql\s*=.*?;/s',
                'private static $globalsToTaintSql= [' . $taintedListSql . '];',
                $pluginCode
            );
            if ($pluginCode === null) {
                echo "[!] An error ocurred while trying to replace the file content\n";
                return false;
            } else {
                if (file_put_contents($filename, $pluginCode) === false) {
                    echo "[!] Unable to write plugin file " . $filename . "\n";
                    return false;
                }
            }
        }
        return true;
    } else {
        echo "[!] Unable to read plugin file " . $filename . "\n";
        return false;
    }
}

function cleanUpDefs(array $assignments, array $primitives)
{
    $output = [];
    foreach ($assignments as $var => $types) {
        foreach ($types as $type) {
            if (!in_array($type, $primitives) && $type !== "mixed") {
                $output[$var] = $type;
                break;
            } else if (in_array($type, $primitives) && !isset($output[$var])) {
                $output[$var] = $type;
            }
        }
        if (!isset($output[$var])) {
            $output[$var] = "mixed";
        }
    }
    return $output;
}

function formatOutput(array $elements)
{
    $output = [];
    foreach ($elements as $key => $val) {
        $parts = explode(".", $key);
        $current =& $output; // we need reference because we are modifying it !
        $parent = null;
        foreach ($parts as $part) {
            if (!isset($current[$part])) {
                $current[$part] = [];
                $current[$part]["children"] = [];
            }
            $parent =& $current[$part];
            $current =& $current[$part]["children"];
        }
        $children = $parent["children"];
        $parent = $val;
        $parent["children"] = $children;
        unset($current);
        unset($parent);
    }
    return $output;
}


// Parsing command line args
$listGlobs = false;
if (count($argv) > 1) {
    if ($argv[1] === "--list") {
        $listGlobs = true;
    }
}

// Creating needed objects for parsing
$parser = (new ParserFactory())->createForNewestSupportedVersion();
$traverser = new NodeTraverser();
// this pass 1 needs to be done before pass two for variable's array
$visitor = new GlobalVarVisitor($listGlobs);
$traverser->addVisitor($visitor);

$files = getAllFiles(".", $skipDirs, "php");

// we parse each file - pass 1
foreach ($files as $file) {
    $code = file_get_contents($file);
    if ($code === false) {
        echo "[!] An error ocurred while trying to read " . $file . "\n";
        // We skip the file, don't error
        continue;
    }
    try {
        $ast = $parser->parse($code);
        if ($ast) {
            $traverser->traverse($ast);
        } //otherwise, we skip the file
    } catch (Exception $e) {
        echo "[!] Parse error in $file: " . $e->getMessage() . "\n";
        //we skip it, we don't error and break the whole execution !
    }
}

// this is pass 2 - uses global vars from pass 1
$visitor2 = new ArrayElemVisitor($visitor->globalVars, $listGlobs, $arrayDepth);
$traverser2 = new NodeTraverser();
$traverser2->addVisitor($visitor2);


// we parse each file - pass 2
foreach ($files as $file) {
    $code = file_get_contents($file);
    if ($code === false) {
        echo "[!] An error ocurred while trying to read " . $file . "\n";
        // We skip the file, don't error
        continue;
    }
    try {
        $ast = $parser->parse($code);
        if ($ast) {
            $traverser2->traverse($ast);
        } //otherwise, we skip the file
    } catch (Exception $e) {
        echo "[!] Parse error in $file: " . $e->getMessage() . "\n";
        //we skip it, we don't error and break the whole execution !
    }
}


// Correct
$allGlobals = array_unique(array_merge(
    array_keys($visitor->globalVars),
    array_keys($visitor2->globalVars)
));

$jsonOutput = [];
foreach ($allGlobals as $global) {
    $jsonOutput[$global] = [];
    $jsonOutput[$global]["name"] = $global;
    $jsonOutput[$global]["taint"] = [];
    $jsonOutput[$global]["taint"]["xss"] = null;
    $jsonOutput[$global]["taint"]["sql"] = null;
}
// print them if user wants to
if ($listGlobs) {
    echo json_encode(formatOutput($jsonOutput));
    exit(0);
}

// we gotta fix this too, but for now let's see if --list works

$assignments1 = cleanUpDefs($visitor->assignments, array_values($visitor->typeMap));
$assignments2 = cleanUpDefs($visitor2->assignments, array_values($visitor2->typeMap));
$allTypes = array_merge($assignments1, $assignments2);


// we now combine assigments and globals to get the type of each global variable
$globalsTypes = [];
foreach ($allGlobals as $globalVar) {
    $globalsTypes[$globalVar] = $allTypes[$globalVar] ?? "mixed";
}

// We now extract the ones that are user input
$safeGlobs = [];
foreach ($globalsTypes as $var => $type) {
    if (in_array($var, $safePatterns)) {
        $safeGlobs[$var] = $type;
    }
}

$psalmParser = new PsalmXMLConfig("psalm.xml");
if ($psalmParser->update($safeGlobs) === false) {
    echo "An error ocurred while trying to update psalm.xml\n";
    exit(1);
}

if (modifyPlugin($psalmPluginsDir, $xssPatterns,$sqlPatterns) === false) {
    echo "An error ocurred while trying to update the plugin code.\n";
    exit(1);
}

echo "[+] Done";
exit(0);
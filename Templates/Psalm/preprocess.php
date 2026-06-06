<?php

/**
 * This are the variables you may edit to adapt it to your codebase
 * - $skipDirs contains the directories that are not going to be checked by the preprocessing step, for example vendor files or migrations
 * - $safePatterns are the patterns for safe global variables
 * - $inputPatterns are the patterns for global variables that may contain use input and have to be tainted
 * Run this script with --globals to get the list of all global variables, and adapt both lists depending on it 
 */

$skipDirs= [];
$safePatterns = [];
$inputPatterns = [];
$psalmPluginsDir="";

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

require_once('vendor/autoload.php');

/**
 * This function returns all the files with extension $extension 
 * in the directory $dir and subdirectories skipping entries containing $skipDirs
 */
function getAllFiles(string $dir, array $skipDirs, string $extension): array{
    $files=[];
    $iterator= new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir,RecursiveDirectoryIterator::SKIP_DOTS));

    foreach($iterator as $file){
        if($file->getExtension() === $extension){
            $path= $file->getPathname();
            $ok=true;
            foreach($skipDirs as $skip){
                if(str_contains($path, DIRECTORY_SEPARATOR . $skip . DIRECTORY_SEPARATOR)){
                    $ok=false;
                    break;
                }
            }
            if($ok){
                array_push($files,$path);
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

class GlobalVarVisitor extends NodeVisitorAbstract{
    public $globalVars=[];
    public $assignments=[];

    private $onlyList=false;

    private $typeMap=[
        Array_::class => "array",
        String_::class => "string",
        Int_::class => "int",
        Float_::class => "float",
        ConstFetch::class => "bool",
        InterpolatedString::class => "string",
        Concat::class => "string"
    ];

    public function __construct(bool $l =false){
        $this->onlyList=$l;
    }

    public function enterNode(Node $node){
        if($node instanceof Global_){
            // we have a global statement
            foreach($node->vars as $var){
                if($var instanceof Variable){
                    $this->globalVars[$var->name]=true;
                }
            }
        }
        else if(!$this->onlyList && $node instanceof Assign){
            $var= $node->var;
            $expr= $node->expr;
            
            if($var instanceof Variable){
                if($expr instanceof New_){
                    if($expr->class instanceof Name){
                        $exprType= implode('\\', $expr->class->getParts());
                    }
                    else{
                        $exprType="mixed";
                    }
                }
                else{
                    $exprType= $this->typeMap[get_class($expr)] ?? "mixed";
                }
                $this->assignments[$var->name]=$exprType;


                if(!isset($exprType)){
                    // null => New_
                    if($expr->class instanceof Name){
                    }
                }else{
                }
            }
        }
    }
}

/**
 * This function checks if the variable looks like a user input depending on the lists above
 */
function isInput(string $name, array $inputs, array $safe): bool{
    $name= strtolower($name);
    foreach($inputs as $pattern){
        if(preg_match("/".$pattern."/",$name)){
            return true;
        }
    }

    foreach($safe as $pattern){
        if(preg_match("/".$pattern."/",$name)){
            return false;
        }
    }

    //if not found, we keep it as input
    return true;
}

/**
 * This class updates the psalm.xml file depending on the given global variables (safe variables, not tainted)
 */
class PsalmXMLConfig{
    private $filePath;

    public function __construct(string $path){
        $this->filePath=$path;
    }

    public function update(array $globalVars):void{
        $xml= new DOMDocument("1.0");
        $xml->preserveWhiteSpace =false;
        $xml->formatOutput= true;
        if($xml->load($this->filePath)){
            $globalsTag= $xml->getElementsByTagName("globals")->item(0);
            if($globalsTag===null){
                // not there yet, we create it
                $globalsTag= $xml->createElement("globals");
                $xml->documentElement->appendChild($globalsTag);
            }
            else{
                //already there, so we clean it
                while($globalsTag->firstChild){
                    $globalsTag->removeChild($globalsTag->firstChild);
                }
            }

            foreach($globalVars as $var => $type){
                // we add the variable and it's type to teh psalm.xml
                $varNode= $xml->createElement("var");
                $varNode->setAttribute("name",$var);
                $varNode->setAttribute("type",$type);
                $globalsTag->appendChild($varNode);
            }

            $xml->save($this->filePath);

        }else{
            echo "[!] Error loading xml file ". $this->filePath. "\n";
        }

    }
}

function modifyPlugin(string $filename, array $taintedGlobals){
    $taintedList= '"' . implode('", "',$taintedGlobals) . '"';
    $pluginCode=file_get_contents($filename);
    if($pluginCode){
        $pluginCode = preg_replace(
            '/private static \$globalstoTaint=.*?;/s',
            'private static $globalstoTaint= [' . $taintedList . '];',
            $pluginCode
        );

        if($pluginCode===null){
            echo "[!] An error ocurred while trying to replace the file content\n";
        }
        else{
            file_put_contents($filename,$pluginCode);
        }
    }
    else{
        echo "[!] Unable to read plugin file ". $filename . "\n";
    }
}

// Parsing command line args
$listGlobs=false;
if(count($argv)>1){
    if($argv[1]==="--global"){
        $listGlobs=true;
    }
}

// Creating needed objects for parsing
$parser   = (new ParserFactory())->createForNewestSupportedVersion();
$traverser = new NodeTraverser();
$visitor  = new GlobalVarVisitor($listGlobs);
$traverser->addVisitor($visitor);

$files=getAllFiles(".",$skipDirs,"php");

// we parse each file
foreach($files as $file){
    $code= file_get_contents($file);
    try{
        $ast= $parser->parse($code);
        if($ast) {
            $traverser->traverse($ast);
        }
    }catch(Exception $e){
        echo "[!] Parse error in $file: " .  $e->getMessage(). "\n";
    }
}

// we now have all the globals var and all the variable assignments
$globals= array_keys($visitor->globalVars);

// print them if user wants to
if($listGlobs){
    echo "[+] Global variables found:\n";
    foreach($globals as $var){
        echo $var."\n";
    }
    exit;
}

$assignments= $visitor->assignments;

// we now combine assigments and globals to get the type of each global variable
$globalsTypes=[];
foreach($globals as $globalVar){
    $globalsTypes[$globalVar]=$assignments[$globalVar] ?? "mixed";
}

// We now extract the ones that are user input
$inputs=[];
$safeGlobs=[];
foreach($globalsTypes as $var => $type){
    if(isInput($var,$inputPatterns,$safePatterns)){
        array_push($inputs,$var);
    }
    else{
        $safeGlobs[$var]=$type;
    }
}

$psalmParser= new PsalmXMLConfig("psalm.xml");
$psalmParser->update($safeGlobs);

modifyPlugin($psalmPluginsDir,$inputs);

echo "[+] Done";
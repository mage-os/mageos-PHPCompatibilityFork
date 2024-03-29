<?php

/*
 * Allowed pre-PHP 7.3.
 */
isset($foo, $bar, $baz);
unset($foo, $bar, $baz);
myFunction($foo, $bar);
$myClosure($foo, $bar);

/*
 * PHP 7.3 trailing commas in function calls + isset + unset.
 */
// Isset & unset.
unset($foo, $bar,);
var_dump(isset($foo, $bar,));

unset(
    $foo,
    $bar,
    $baz,
);

// Function calls, including calls to methods and closures.
echo $twig->render(
    'index.html',
    compact('title', 'body', 'comments',), // x2.
);

$newArray = \array_merge(
    $arrayOne,
    $arrayTwo,
    ['foo', 'bar'],
);

var_dump($whatIsInThere, $probablyABugInThisOne, $oneMoreToCheck,);

$text = SomeNameSpace\PartTwo\PartThree\functionName($en, 'comma', 'Jane',);

$foo = new Foo( 'constructor', 'bar', );

$foo->bar(
  'method',
  'bar',
);

$foo( 'invoke','bar' , );

MyNamespace\Foo::bar('method','bar',);

$bar = function(...$args) {};
$bar('arg1', 'arg2',);

/*
 * Still not allowed.
 */
// Trailing comma in function declaration. Update: Allowed since PHP 8.0, but not the concern of this sniff.
function bar($a, $b,) {}
$closure = function ($a, $b,) {}

// Free-standing comma.
foo(,); // Parse error, but throw an error anyway.

// Multiple trailing commas.
foo('function', 'bar',,); // Parse error, but throw an error anyway.

// Leading comma.
foo(, 'function', 'bar'); // Parse error, but not our concern.

// List with trailing comma.
list($drink, $color, $power, ) = $info; // Was already allowed.

// Safeguard that closure use statements with trailing commas are ignored.
// This is allowed since PHP 8.0, but not the concern of this sniff.
$closure = function () use( $a, $b, ) {};

// Prevent false positives on function declarations with return by reference.
function &bar($a, $b,) {}

// Examine some more constructs.
$obj = new MyClass($param);
$obj = new self($param);
$obj = new parent($param);
$obj = new static($param);
$anon = new class($param) {};

// ... but prevent false positives on function declarations with return by reference when the function name is a reserved keyword.
// The underlying tokenizer issue should be fixed in PHPCS itself.
class Foo {
    function &parent($a, $b,) {}
    function &self($a, $b,) {}
}

// These should be flagged.
$obj = new MyClass($param,);
$obj = new self($param, );
$obj = new parent($param , );
$obj = new static($param,);
$anon = new class($param,) {};

// Safeguard against false positives on arrow function declarations.
$arrow = fn ($a, $b,) => $a * $b;

// Safeguard that trailing comma's in method calls using PHP 8.0+ nullsafe object operator are flagged correctly.
$foo?->bar( 'method', 'bar', );

// Safeguard that trailing comma's in class instantiations in PHP 8.0+ attributes are flagged correctly.
#[Foo( 'constructor', 'bar', )]
function bar() {}

// Document how trailing comma's in PHP 8.1+ first class callables are handled.
register_callback(strtolower(...,)); // Parse error, but throw an error anyway as the calllable is by rights a function call.

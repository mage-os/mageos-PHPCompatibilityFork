<?php
class foo {
    function foo() {
        echo 'I am the constructor - but I shouldn\'t be';
    }
}

class bar {
    function bar() {
        echo 'I am just the bar method';
    }
    function __construct() {
        echo 'I am the real constructor';
    }
}

class barFOO {
    function BARfoo() {
        echo 'I am the constructor - but I shouldn\'t be';
    }
}

namespace foobar {

    class foobar {
        function foobar() {
            echo 'I am just the foobar method';
        }
    }
}

class floo {
    abstract public function floo();
}

interface MyInterface {
    function MyInterface();
}

interface MySecondInterface {
    function MySecondInterface();
    function __construct();
}

$a = new class
{
    public function someThing($name) {}
}

class Nested {
    public function getAnonymousClass() {
        return new class() {
            public function nested() {
                echo 'In method nested!';
            }
        };
    }
}

// Testing empty/invalid class name condition.
class new {}

// Testing empty/invalid function name condition.
class InvalidSwitchFunctionName {
    function switch() {}
    function InvalidSwitchFunctionName() {}
}

// Simple test of the docblock skipping code.
class bar {
    /**
     * This
     * docblock
     * should be
     * skipped
     * over.
     */
    #[SomeAttribute('param', CONSTANT), OtherAttribute]
    function __construct() {
        echo 'I am the real constructor';
    }
}

// Class vs function name PHP case-sensitivity quirks.
class FooBÃÈ {
    function fOOBÃÈ() {}
    function FooBãè() {} // OK - not PHP 4-type constructor - POC: https://3v4l.org/YOc2R.
}

// Must be last test: testing class without scope closer.
class Something {

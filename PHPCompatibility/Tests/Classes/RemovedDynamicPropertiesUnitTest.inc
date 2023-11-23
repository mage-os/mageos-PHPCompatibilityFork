<?php
/**
 * This file has been modified by Adobe.
 * All modifications are Copyright 2023 Adobe.
 * All Rights Reserved.
 *
 * PHPCompatibility, an external standard for PHP_CodeSniffer.
 *
 * @package   PHPCompatibility
 * @copyright 2012-2023 PHPCompatibility Contributors
 * @license   https://opensource.org/licenses/LGPL-3.0 LGPL3
 * @link      https://github.com/PHPCompatibility/PHPCompatibility
 */
trait TraitA
{
    private bool $prop2;
}

trait TraitB
{
    private bool $prop3;
}

class Bar
{
    public bool $prop1;

    public function resetProp1()
    {
        $this->prop1 = false;
    }
}

#[\AllowDynamicProperties]
class Baz
{
    public bool $prop1;

    public function resetProp1()
    {
        $this->prop1 = false;
    }
}

/**
 * @property bool $prop6 full format
 * @property $prop7 prop without type
 * @property bool prop8 prop with comment
 */
class Foo1
{
    private bool $prop4;
    public function __construct(
        private bool $prop5
    ) {
    }

    private function reset(): void
    {
        $this->resetProp1();
        $this->prop1 = false;
        $this->prop2 = false;
        $this->prop3 = false;
        $this->prop4 = false;
        $this->prop5 = false;
        $this->prop6 = false;
        $this->prop7 = false;
        $this->prop8 = false;
        $this/** a comment */ ->/** another comment*/ prop9 = false;
        $this->setSomething($this->prop9);
        $prop9 = $this->prop9;
        $this::$prop9 = false;
        $this->prop4->prop9 = false;
        $thisVar = $this;
        $thisVar->prop9 = false; // undetermined context
        $thisVar->$this->prop9 = false; // false positive
    }
}

class Foo2
{
    private bool $prop4;
    public function __construct(
        private bool $prop5
    ) {
    }

    private function reset(): void
    {
        $this->resetProp1();
        $this->prop1 = false;
        $this->prop2 = false;
        $this->prop3 = false;
        $this->prop4 = false;
        $this->prop5 = false;
        $this->prop6 = false;
        $this->prop7 = false;
        $this->prop8 = false;
        $this/** a comment */ ->/** another comment*/ prop9 = false;
        $this->setSomething($this->prop9);
        $prop9 = $this->prop9;
        $this::$prop9 = false;
        $this->prop4->prop9 = false;
        $thisVar = $this;
        $thisVar->prop9 = false; // undetermined context
        $thisVar->$this->prop9 = false; // false positive
    }

    public function setSomething()
    {

    }
}

/**
 * @property bool $prop6 full format
 * @property $prop7 prop without type
 * @property bool prop8 prop with comment
 */
class Foo3 extends Bar
{
    use TraitA, TraitB;
    private bool $prop4;
    public function __construct(
        private bool $prop5
    ) {
    }

    private function reset(): void
    {
        $this->resetProp1();
        $this->prop1 = false;
        $this->prop2 = false;
        $this->prop3 = false;
        $this->prop4 = false;
        $this->prop5 = false;
        $this->prop6 = false;
        $this->prop7 = false;
        $this->prop8 = false;
        $this->prop9 = false;
    }
}

/**
 * @property bool $prop6 full format
 * @property $prop7 prop without type
 * @property bool prop8 prop with comment
 */
class Foo4
{
    use TraitA, TraitB;
    private bool $prop4;
    public function __construct(
        private bool $prop5
    ) {
    }

    private function reset(): void
    {
        $this->resetProp1();
        $this->prop1 = false;
        $this->prop2 = false;
        $this->prop3 = false;
        $this->prop4 = false;
        $this->prop5 = false;
        $this->prop6 = false;
        $this->prop7 = false;
        $this->prop8 = false;
        $this->prop9 = false;
    }
}

/**
 * @property bool $prop6 full format
 * @property $prop7 prop without type
 * @property bool prop8 prop with comment
 */
class Foo5 extends Bar
{
    private bool $prop4;
    public function __construct(
        private bool $prop5
    ) {
    }

    private function reset(): void
    {
        $this->resetProp1();
        $this->prop1 = false;
        $this->prop2 = false;
        $this->prop3 = false;
        $this->prop4 = false;
        $this->prop5 = false;
        $this->prop6 = false;
        $this->prop7 = false;
        $this->prop8 = false;
        $this->prop9 = false;
    }
}

/**
 * @property bool $prop6 full format
 * @property $prop7 prop without type
 * @property bool prop8 prop with comment
 */
#[\AllowDynamicProperties]
class Foo5
{
    private bool $prop4;
    public function __construct(
        private bool $prop5
    ) {
    }

    private function reset(): void
    {
        $this->resetProp1();
        $this->prop1 = false;
        $this->prop2 = false;
        $this->prop3 = false;
        $this->prop4 = false;
        $this->prop5 = false;
        $this->prop6 = false;
        $this->prop7 = false;
        $this->prop8 = false;
        $this->prop9 = false;
    }
}

/**
 * @property bool $prop6 full format
 * @property $prop7 prop without type
 * @property bool prop8 prop with comment
 */
class Foo5
{
    private bool $prop4;
    public function __construct(
        private bool $prop5
    ) {
    }

    private function reset(): void
    {
        $this->resetProp1();
        $this->prop1 = false;
        $this->prop2 = false;
        $this->prop3 = false;
        $this->prop4 = false;
        $this->prop5 = false;
        $this->prop6 = false;
        $this->prop7 = false;
        $this->prop8 = false;
        $this->prop9 = false;
    }

    public function __set($name, $value)
    {
        //do something
    }
}

$object->prop9 = false;
$object->reset();

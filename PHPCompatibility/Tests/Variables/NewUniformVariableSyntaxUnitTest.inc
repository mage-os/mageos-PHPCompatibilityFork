<?php

// Variable variables with changed behaviour between PHP 5 and PHP 7.
echo $$var['key1']['key2'];
echo $obj->$var['key'];
echo $obj->$var['key']();
echo myClass::$var['key']();
echo myClass::$var['key1']['key2']['key3']();

// Variable variables which will be interpreted the same in PHP 5 and PHP 7.
echo ${$var['key1']['key2']};
echo $obj->{$var['key']};
echo $obj->{$var['key']}();
echo myClass::{$var['key']}();
echo myClass::{$var['key1']['key2']['key3']}();

// Variable variables we're not sniffing for and other potential false positives.
echo $$foo;
echo "${foo}";
echo $var['key1']['key2'];
echo $obj->var['key'];
echo $obj->hello();
echo myClass::$foo;
echo myClass::$var['key'];
echo myClass::hello();
echo ${$obj->getName()};
echo $obj->{$obj->$hello}();
echo $obj->{myClass::$foo}();

// Uh oh, these were false negatives. Reporting them now.
class fooBar extends Bar{
    function foo() {
        echo new self::$transport[$cap_string]();
        echo static::$transport[$cap_string]();
        echo parent::$transport[$cap_string]();
    }
}

// Test code style independent sniffing.
echo $  $var['key1']['key2']; // Bad.
echo $obj  ->   /* comment */ $var['key']; // Bad.
echo myClass  :: { /* comment */ $var['key']}(); // OK.

// Make sure PHP 8.0+ nullsafe object operator is handled correctly.
echo $obj?->$var['key'];
echo $obj?->$var['key']();
echo $obj?->{$var['key']};
echo $obj?->{$var['key']}();

// Live coding.
echo $$var['key'

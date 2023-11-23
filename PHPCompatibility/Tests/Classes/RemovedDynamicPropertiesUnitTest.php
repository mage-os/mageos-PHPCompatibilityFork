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

namespace PHPCompatibility\Tests\Classes;

use PHPCompatibility\Tests\BaseSniffTestCase;

/**
 * Test the RemovedDynamicProperties sniff.
 *
 * @group removedDynamicProperties
 * @group classes
 *
 * @covers \PHPCompatibility\Sniffs\Classes\RemovedDynamicPropertiesSniff
 */
class RemovedDynamicPropertiesUnitTest extends BaseSniffTestCase
{

    /**
     * Verify a deprecation warning is thrown if a dynamic property is found in a class.
     *
     * @param int    $line     The line number in the test file.
     * @param string $property The dynamic property name.
     *
     * @return void
     *
     * @dataProvider dataProvider
     */
    public function testCreationOfDynamicProperty($line, $property)
    {
        $file = $this->sniffFile(__FILE__, '8.2');
        $this->assertWarning(
            $file,
            $line,
            'Creation of dynamic property ' . $property . ' is deprecated since PHP 8.2'
        );
    }

    /**
     * Verify the sniff does not throw false positives for valid code.
     *
     * @return void
     */
    public function testNoFalsePositives()
    {
        $file       = $this->sniffFile(__FILE__, '8.2');
        $totalLines = substr_count(file_get_contents(\str_replace('UnitTest.php', 'UnitTest.inc', __FILE__)), PHP_EOL);
        foreach (static::dataProvider() as $error) {
            $errorLines[$error[0]] = true;
        }

        for ($line = 1; $line <= $totalLines; $line++) {
            if (isset($errorLines[$line])) {
                continue;
            }
            $this->assertNoViolation($file, $line);
        }
    }

    /**
     * Verify no notices are thrown at all.
     *
     * @return void
     */
    public function testNoViolationsInFileOnValidVersion()
    {
        $file = $this->sniffFile(__FILE__, '8.1');
        $this->assertNoViolation($file);
    }

    /**
     * Data provider.
     *
     * @return array
     *
     * @see testCreationOfDynamicProperty()
     */
    public static function dataProvider()
    {
        return [
            [61, 'Foo1::$prop1'],
            [62, 'Foo1::$prop2'],
            [63, 'Foo1::$prop3'],
            [66, 'Foo1::$prop6'],
            [67, 'Foo1::$prop7'],
            [68, 'Foo1::$prop8'],
            [69, 'Foo1::$prop9'],
            [91, 'Foo2::$prop1'],
            [92, 'Foo2::$prop2'],
            [93, 'Foo2::$prop3'],
            [96, 'Foo2::$prop6'],
            [97, 'Foo2::$prop7'],
            [98, 'Foo2::$prop8'],
            [99, 'Foo2::$prop9'],
        ];
    }
}

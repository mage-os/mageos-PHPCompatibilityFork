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

namespace PHPCompatibility\Tests\ParameterValues;

use PHPCompatibility\Tests\BaseSniffTestCase;

/**
 * Test the RemovedMbStringEncodings sniff.
 *
 * @group removedMbStringEncodings
 * @group parameterValues
 *
 * @covers \PHPCompatibility\Sniffs\ParameterValues\RemovedMbStringEncodingsSniff
 */
class RemovedMbStringEncodingsUnitTest extends BaseSniffTestCase
{

    /**
     * List of disallowed encodings and their alternatives.
     *
     * @var string[]
     */
    private $disallowedEncodings = [
        'qprint' => [
            'name' => 'QPrint',
            'alternative' => 'quoted_printable_encode/quoted_printable_decode',
        ],
        'quoted-printable' => [
            'name' => 'QPrint',
            'alternative' => 'quoted_printable_encode/quoted_printable_decode',
        ],
        'base64' => [
            'name' => 'Base64',
            'alternative' => 'base64_encode/base64_decode',
        ],
        'uuencode' => [
            'name' => 'Uuencode',
            'alternative' => 'convert_uuencode/convert_uudecode',
        ],
        'html-entities' => [
            'name' => 'HTML entities',
            'alternative' => 'htmlspecialchars, htmlentities, or mb_encode_numericentity/mb_decode_numericentity',
        ],
        'html' => [
            'name' => 'HTML entities',
            'alternative' => 'htmlspecialchars, htmlentities, or mb_encode_numericentity/mb_decode_numericentity',
        ],
    ];

    /**
     * Verify a deprecation warning is thrown if MBString function is used with encodings: QPrint,BASE64,UUENCODE,HTML
     *
     * @param string $encoding the disallowed encoding
     * @param int    $start    the start line number
     * @param int    $end      the end line number
     *
     * @return void
     *
     * @dataProvider usageOfDeprecatedEncodingsInMbStringFunctionsDataProvider
     */
    public function testUsageOfDeprecatedEncodingsInMbStringFunctions($encoding, $start, $end)
    {
        $file = $this->sniffFile(__FILE__, '8.2');
        // No errors expected on the first 11 lines.
        for ($line = $start; $line <= $end; $line++) {
            $this->assertWarning(
                $file,
                $line,
                sprintf(
                    'Handling %s via mbstring is deprecated since PHP 8.2; Use %s instead',
                    $this->disallowedEncodings[$encoding]['name'],
                    $this->disallowedEncodings[$encoding]['alternative']
                )
            );
        }
    }

    /**
     * Data provider.
     *
     * @see testUsageOfDeprecatedEncodingsInMbStringFunctions()
     *
     * @return array
     */
    public static function usageOfDeprecatedEncodingsInMbStringFunctionsDataProvider()
    {
        return [
            ['base64', 15, 41],
            ['qprint', 44, 70],
            ['quoted-printable', 73, 99],
            ['uuencode', 102, 128],
            ['html-entities', 131, 157],
            ['html', 160, 186],
        ];
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

        for ($line = 190; $line <= $totalLines; $line++) {
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
}

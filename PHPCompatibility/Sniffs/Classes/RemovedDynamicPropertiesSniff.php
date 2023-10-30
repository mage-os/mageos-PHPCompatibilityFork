<?php
/**
 * This file has been modified by Adobe.
 * All modifications are Copyright 2023 Adobe.
 * All Rights Reserved.
 *
 * PHPCompatibility, an external standard for PHP_CodeSniffer.
 *
 * @package   PHPCompatibility
 * @copyright 2012-2020 PHPCompatibility Contributors
 * @license   https://opensource.org/licenses/LGPL-3.0 LGPL3
 * @link      https://github.com/PHPCompatibility/PHPCompatibility
 */

namespace PHPCompatibility\Sniffs\Classes;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Util\Tokens;
use PHPCompatibility\Helpers\ScannedCode;
use PHPCompatibility\Sniff;
use PHPCSUtils\Internal\Cache;
use PHPCSUtils\Utils\Conditions;
use PHPCSUtils\Utils\FunctionDeclarations;
use PHPCSUtils\Utils\Namespaces;
use PHPCSUtils\Utils\ObjectDeclarations;
use PHPCSUtils\Utils\Scopes;
use PHPCSUtils\Utils\UseStatements;

/**
 * Reports usage of dynamic properties in classes as deprecated.
 *
 * As of PHP 8.2, The creation of dynamic properties is deprecated, unless the class opts in by using
 * the #[\AllowDynamicProperties] attribute. stdClass allows dynamic properties.
 * Usage of the __get()/__set() magic methods is not affected by this change.
 *
 * PHP version 8.2
 *
 * @link https://www.php.net/manual/en/migration82.deprecated.php#migration82.deprecated.core.dynamic-properties
 */
class RemovedDynamicPropertiesSniff extends Sniff
{

    /**
     * List of tags that declare a magic property.
     *
     * @var string[]
     */
    private $magicPropertyTags = [
        '@property',
        '@property-read',
        '@property-write',
    ];

    /**
     * Registers the tokens that this sniff wants to listen for.
     *
     * @return array
     */
    public function register()
    {
        return [
            \T_OBJECT_OPERATOR,
            \T_NULLSAFE_OBJECT_OPERATOR,
        ];
    }

    /**
     * Processes this test, when one of its tokens is encountered.
     *
     * @param File $phpcsFile The file being scanned.
     * @param int  $stackPtr  The position of the current token in the stack passed in $tokens.
     *
     * @return int|void Integer stack pointer to skip forward or void to continue
     *                  normal file processing.
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        if (ScannedCode::shouldRunOnOrAbove('8.2') === false) {
            return;
        }

        $tokens = $phpcsFile->getTokens();

        // Check if pointer is inside a class.
        $classPtr = Conditions::getLastCondition($phpcsFile, $stackPtr, [\T_CLASS]);
        if ($classPtr === false) {
            return;
        }

        // Check if it is string.
        $propertyNamePtr = $phpcsFile->findNext(Tokens::$emptyTokens, $stackPtr + 1, null, true);
        if ($propertyNamePtr === false || $tokens[$propertyNamePtr]['code'] !== \T_STRING) {
            return;
        }

        $afterPropertyNamePtr = $phpcsFile->findNext(Tokens::$emptyTokens, ($propertyNamePtr + 1), null, true);
        // Check if it is not a method call.
        if ($tokens[$afterPropertyNamePtr]['code'] === \T_OPEN_PARENTHESIS) {
            return;
        }

        // Check if it is a property access on $this.
        $thisPtr = $phpcsFile->findPrevious(Tokens::$emptyTokens, $stackPtr - 1, null, true);
        if ($thisPtr === false
            || $tokens[$thisPtr]['code'] !== \T_VARIABLE
            || $tokens[$thisPtr]['content'] !== '$this'
        ) {
            return;
        }

        // Check if it is a direct property access.
        $beforeThisPtr = $phpcsFile->findPrevious(Tokens::$emptyTokens, $thisPtr - 1, null, true);
        if ($beforeThisPtr &&
            \in_array(
                $tokens[$beforeThisPtr]['code'],
                [\T_OBJECT_OPERATOR, \T_NULLSAFE_OBJECT_OPERATOR, \T_DOUBLE_COLON]
            )
        ) {
            return;
        }

        $propertyName = $tokens[$propertyNamePtr]['content'];
        if (\in_array($propertyName, $this->getClassDeclaredProperties($phpcsFile, $classPtr), true)
            || \in_array($propertyName, $this->getClassPromotedProperties($phpcsFile, $classPtr), true)
            || \in_array($propertyName, $this->getClassMagicProperties($phpcsFile, $classPtr), true)
        ) {
            return;
        }

        $className = ObjectDeclarations::getName($phpcsFile, $classPtr);
        $namespace = Namespaces::determineNamespace($phpcsFile, $classPtr);
        if ($namespace !== '') {
            $className = $namespace . '\\' . $className;
        }

        if (!$this->isClassUsingTraits($phpcsFile, $classPtr)
            && ObjectDeclarations::findExtendedClassName($phpcsFile, $classPtr) === false
        ) {
            $error = 'Access to an undefined property %s::$%s;' .
                ' Creation of dynamic property is deprecated since PHP 8.2';
            $data  = [$className, $propertyName];
            $phpcsFile->addWarning($error, $propertyNamePtr, 'Deprecated', $data);
        }
    }

    /**
     * Get properties declared in the scope class
     *
     * @param File $phpcsFile The file being scanned.
     * @param int  $stackPtr  The position of the current token in the stack passed in $tokens.
     *
     * @return string[]
     */
    private function getClassDeclaredProperties(File $phpcsFile, $stackPtr)
    {
        if (Cache::isCached($phpcsFile, __METHOD__, $stackPtr) === true) {
            return Cache::get($phpcsFile, __METHOD__, $stackPtr);
        }
        $tokens     = $phpcsFile->getTokens();
        $properties = [];
        $next       = $stackPtr;
        while ($next = $this->findInClass($phpcsFile, $stackPtr, $next + 1, \T_VARIABLE)) {
            if (Scopes::isOOProperty($phpcsFile, $next) !== false) {
                $properties[] = \ltrim($tokens[$next]['content'], '$');
            }
        }
        Cache::set($phpcsFile, __METHOD__, $stackPtr, $properties);
        return $properties;
    }

    /**
     * Get properties declared in the constructor method
     *
     * @param File $phpcsFile The file being scanned.
     * @param int  $stackPtr  The position of the current token in the stack passed in $tokens.
     *
     * @return string[]
     */
    private function getClassPromotedProperties(File $phpcsFile, $stackPtr)
    {
        if (Cache::isCached($phpcsFile, __METHOD__, $stackPtr) === true) {
            return Cache::get($phpcsFile, __METHOD__, $stackPtr);
        }
        $properties = [];
        $next       = $stackPtr;
        while ($next = $this->findInClass($phpcsFile, $stackPtr, $next + 1, \T_FUNCTION)) {
            if (Scopes::isOOMethod($phpcsFile, $next)
                && \strtolower(FunctionDeclarations::getName($phpcsFile, $next)) === '__construct'
            ) {
                $params = FunctionDeclarations::getParameters($phpcsFile, $next);
                foreach ($params as $param) {
                    if (isset($param['property_visibility']) === true) {
                        $properties[] = \ltrim($param['name'], '$');
                    }
                }
                break;
            }
        }
        Cache::set($phpcsFile, __METHOD__, $stackPtr, $properties);
        return $properties;
    }

    /**
     * Find magic properties declared in the class PHPDoc
     *
     * @param File $phpcsFile The file being scanned.
     * @param int  $stackPtr  The position of the current token in the stack passed in $tokens.
     *
     * @return string[]
     */
    public function getClassMagicProperties(File $phpcsFile, $stackPtr)
    {
        if (Cache::isCached($phpcsFile, __METHOD__, $stackPtr) === true) {
            return Cache::get($phpcsFile, __METHOD__, $stackPtr);
        }
        $properties      = [];
        $tokens          = $phpcsFile->getTokens();
        $commentStartPtr = $this->findDocCommentOpenTag($phpcsFile, $stackPtr);
        if ($commentStartPtr === -1) {
            return [];
        }
        foreach ($tokens[$commentStartPtr]['comment_tags'] as $tag) {
            $token = $tokens[$tag];
            if (!\in_array($token['content'], $this->magicPropertyTags, true)
                || $tokens[($tag + 2)]['code'] !== \T_DOC_COMMENT_STRING
            ) {
                continue;
            }
            $commentParts = \preg_split('/\s+/', (string)$tokens[($tag + 2)]['content'], 3);
            if (\strpos($commentParts[0], '$') === 0) {
                $properties[] = \ltrim($commentParts[0], '$');
            } elseif (isset($commentParts[1])) {
                $properties[] = \ltrim($commentParts[1], '$');
            }
        }
        Cache::set($phpcsFile, __METHOD__, $stackPtr, $properties);
        return $properties;
    }

    /**
     * Check if class uses traits
     *
     * @param File $phpcsFile The file being scanned.
     * @param int  $stackPtr  The position of the current token in the stack passed in $tokens.
     *
     * @return bool
     */
    private function isClassUsingTraits(File $phpcsFile, $stackPtr)
    {
        if (Cache::isCached($phpcsFile, __METHOD__, $stackPtr) === true) {
            return Cache::get($phpcsFile, __METHOD__, $stackPtr);
        }
        $usesTraits = false;
        $next       = $stackPtr;
        while ($next = $this->findInClass($phpcsFile, $stackPtr, $next + 1, \T_USE)) {
            if (UseStatements::isTraitUse($phpcsFile, $next) === true) {
                $usesTraits = true;
                break;
            }
        }
        Cache::set($phpcsFile, __METHOD__, $stackPtr, $usesTraits);
        return $usesTraits;
    }

    /**
     * Find token in class scope
     *
     * @param File             $phpcsFile  The file being scanned.
     * @param int              $classPtr   The position of the class in the stack passed in $tokens.
     * @param int              $currentPtr The position of the current token in the stack passed in $tokens.
     * @param array|int|string $needle     The token to search for.
     *
     * @return int|false
     */
    private function findInClass(File $phpcsFile, $classPtr, $currentPtr, $needle)
    {
        $tokens          = $phpcsFile->getTokens();
        $classScopeEnd   = $tokens[$classPtr]['scope_closer'];
        $classScopeStart = $tokens[$classPtr]['scope_opener'];
        return $phpcsFile->findNext($needle, \max($currentPtr, $classScopeStart), $classScopeEnd);
    }

    /**
     * Finds matching PHPDoc for current pointer
     *
     * @param File $phpcsFile The file being scanned.
     * @param int  $stackPtr  The position of the current token in the stack passed in $tokens.
     *
     * @return int
     */
    private function findDocCommentOpenTag(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();

        $commentStartPtr = $phpcsFile->findPrevious(
            [
                T_WHITESPACE,
                T_DOC_COMMENT_STAR,
                T_DOC_COMMENT_WHITESPACE,
                T_DOC_COMMENT_TAG,
                T_DOC_COMMENT_STRING,
                T_DOC_COMMENT_CLOSE_TAG,
            ],
            $stackPtr - 1,
            null,
            true,
            null,
            true
        );

        if ($tokens[$commentStartPtr]['code'] !== T_DOC_COMMENT_OPEN_TAG) {
            return -1;
        }

        return $commentStartPtr;
    }
}

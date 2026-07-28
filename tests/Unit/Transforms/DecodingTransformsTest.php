<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Transforms;

use Kanopi\Crs\Transforms\CssDecodeTransform;
use Kanopi\Crs\Transforms\EscapeSeqDecodeTransform;
use Kanopi\Crs\Transforms\JsDecodeTransform;
use Kanopi\Crs\Transforms\NormalisePathTransform;
use Kanopi\Crs\Transforms\NormalizePathWinTransform;
use Kanopi\Crs\Transforms\RemoveCommentsCharTransform;
use Kanopi\Crs\Transforms\TransformRegistry;
use PHPUnit\Framework\TestCase;

/**
 * The anti-evasion transforms CRS asks for and this engine was skipping — 76
 * occurrences across 52 rules, every one of them matching against
 * less-normalised input than upstream intends.
 */
final class DecodingTransformsTest extends TestCase
{
    public function testAllPreviouslyMissingTransformsAreRegistered(): void
    {
        $transformRegistry = new TransformRegistry();

        $names = [
            'normalizePath', 'normalisePath', 'normalizePathWin',
            'jsDecode', 'cssDecode', 'escapeSeqDecode', 'removeCommentsChar',
        ];
        foreach ($names as $name) {
            $this->assertTrue($transformRegistry->has($name), $name . ' should be registered.');
        }
    }

    public function testBothPathSpellingsResolveToTheSameTransform(): void
    {
        $transformRegistry = new TransformRegistry();

        $this->assertSame(
            $transformRegistry->get('normalizePath'),
            $transformRegistry->get('normalisePath'),
            'CRS writes the z spelling; this project grew up on the s. Both must work.'
        );
    }

    // --- jsDecode ------------------------------------------------------------

    /**
     * @return \Iterator<string, array{string, string}>
     */
    public static function jsDecodeProvider(): \Iterator
    {
        yield 'unicode escape' => ['\u0061lert(1)', 'alert(1)'];
        yield 'hex escape' => ['\x3cscript\x3e', '<script>'];
        yield 'fullwidth folds to ascii' => ['\uff1cscript\uff1e', '<script>'];
        yield 'control escapes' => ['a\tb\nc', "a\tb\nc"];
        yield 'escaped backslash' => ['a\\\\b', 'a\b'];
        yield 'unknown escape drops the backslash' => ['\q', 'q'];
        yield 'nothing to do' => ['plain text', 'plain text'];
        yield 'trailing backslash survives' => ['abc\\', 'abc\\'];
        yield 'incomplete hex is not an escape' => ['\x3', 'x3'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('jsDecodeProvider')]
    public function testJsDecode(string $input, string $expected): void
    {
        $this->assertSame($expected, (new JsDecodeTransform())->apply($input));
    }

    // --- cssDecode -----------------------------------------------------------

    /**
     * @return \Iterator<string, array{string, string}>
     */
    public static function cssDecodeProvider(): \Iterator
    {
        yield 'short hex plus space' => ['\65 xpression(1)', 'expression(1)'];
        yield 'six-digit hex' => ['\000075rl(x)', 'url(x)'];
        yield 'hex run ends at a non-hex char' => ['\65xpression', 'expression'];
        // Single-quoted, or PHP reads \65 as an octal escape before we ever see it.
        yield 'tab also terminates the escape' => ['\65' . "\t" . 'x', 'ex'];
        yield 'escaped literal' => ['\:', ':'];
        yield 'line continuation removed' => ["a\\\nb", 'ab'];
        yield 'nothing to do' => ['color: red', 'color: red'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('cssDecodeProvider')]
    public function testCssDecode(string $input, string $expected): void
    {
        $this->assertSame($expected, (new CssDecodeTransform())->apply($input));
    }

    // --- escapeSeqDecode -----------------------------------------------------

    /**
     * @return \Iterator<string, array{string, string}>
     */
    public static function escapeSeqProvider(): \Iterator
    {
        yield 'hex' => ['cat\x20/etc/passwd', 'cat /etc/passwd'];
        yield 'octal' => ['cat\040/etc/passwd', 'cat /etc/passwd'];
        yield 'control' => ['a\tb', "a\tb"];
        yield 'unknown escape keeps its backslash' => ['\q', '\q'];
        yield 'nothing to do' => ['plain', 'plain'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('escapeSeqProvider')]
    public function testEscapeSeqDecode(string $input, string $expected): void
    {
        $this->assertSame($expected, (new EscapeSeqDecodeTransform())->apply($input));
    }

    // --- removeCommentsChar --------------------------------------------------

    public function testRemoveCommentsCharKeepsTheBodyUnlikeRemoveComments(): void
    {
        $removeCommentsCharTransform = new RemoveCommentsCharTransform();

        $this->assertSame('SELxECT', $removeCommentsCharTransform->apply('SEL/*x*/ECT'));
        $this->assertSame('SELECT', $removeCommentsCharTransform->apply('SEL--ECT'));
        $this->assertSame('SELECT', $removeCommentsCharTransform->apply('SEL<!--ECT'));
        $this->assertSame('plain', $removeCommentsCharTransform->apply('plain'));
    }

    // --- normalizePath -------------------------------------------------------

    /**
     * An unresolvable traversal is preserved, matching Apache's ap_getparents()
     * which ModSecurity follows. This is the property that makes the transform
     * safe to enable: the 930 rules match on `../` being present, and cancelling
     * a leading traversal against nothing would have removed the evidence.
     *
     * @return \Iterator<string, array{string, string}>
     */
    public static function normalizePathProvider(): \Iterator
    {
        yield 'leading traversal is preserved' => ['../../etc/passwd', '../../etc/passwd'];
        yield 'resolvable traversal collapses' => ['/var/www/../../etc/passwd', '/etc/passwd'];
        yield 'mid-path traversal' => ['a/b/../c', 'a/c'];
        yield 'current directory' => ['./x', 'x'];
        yield 'duplicate slashes' => ['a//b', 'a/b'];
        yield 'trailing slash kept' => ['/a/./b/', '/a/b/'];
        yield 'absolute cannot climb above root' => ['/../etc', '/etc'];
        yield 'bare traversal' => ['..', '..'];
        yield 'empty' => ['', ''];
        yield 'root' => ['/', '/'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('normalizePathProvider')]
    public function testNormalizePath(string $input, string $expected): void
    {
        $this->assertSame($expected, (new NormalisePathTransform())->apply($input));
    }

    public function testNormalizePathWinConvertsSeparatorsFirst(): void
    {
        $normalizePathWinTransform = new NormalizePathWinTransform();

        $this->assertSame('../../windows/win.ini', $normalizePathWinTransform->apply('..\\..\\windows\\win.ini'));
        $this->assertSame('c:/windows/win.ini', $normalizePathWinTransform->apply('c:\\windows\\.\\win.ini'));
        $this->assertSame('/etc/passwd', $normalizePathWinTransform->apply('/var\\..\\..\\etc/passwd'));
    }

    public function testTransformsAreIdempotentOnAlreadyCleanInput(): void
    {
        // A transform that mangles ordinary text is a false-positive engine.
        $clean = 'The quick brown fox jumps over the lazy dog. 42 + 8 = 50.';

        $transforms = [
            new JsDecodeTransform(),
            new CssDecodeTransform(),
            new EscapeSeqDecodeTransform(),
            new RemoveCommentsCharTransform(),
        ];
        foreach ($transforms as $transform) {
            $this->assertSame($clean, $transform->apply($clean), $transform->name() . ' altered clean text.');
        }
    }
}

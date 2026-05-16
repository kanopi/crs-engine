<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Transforms;

use Kanopi\Crs\Transforms\Base64DecodeTransform;
use Kanopi\Crs\Transforms\CmdLineTransform;
use Kanopi\Crs\Transforms\CompressWhitespaceTransform;
use Kanopi\Crs\Transforms\HtmlEntityDecodeTransform;
use Kanopi\Crs\Transforms\LengthTransform;
use Kanopi\Crs\Transforms\LowercaseTransform;
use Kanopi\Crs\Transforms\NormalisePathTransform;
use Kanopi\Crs\Transforms\RemoveCommentsTransform;
use Kanopi\Crs\Transforms\RemoveNullsTransform;
use Kanopi\Crs\Transforms\RemoveWhitespaceTransform;
use Kanopi\Crs\Transforms\ReplaceCommentsTransform;
use Kanopi\Crs\Transforms\UrlDecodeTransform;
use Kanopi\Crs\Transforms\UrlDecodeUniTransform;
use Kanopi\Crs\Transforms\Utf8ToUnicodeTransform;
use PHPUnit\Framework\TestCase;

final class TransformsTest extends TestCase
{
    public function testLowercase(): void
    {
        $this->assertSame('hello world', (new LowercaseTransform())->apply('Hello World'));
        $this->assertSame('café', (new LowercaseTransform())->apply('CAFÉ'));
    }

    public function testUrlDecode(): void
    {
        $this->assertSame("' OR 1=1", (new UrlDecodeTransform())->apply("%27%20OR%201%3D1"));
    }

    public function testUrlDecodeUni(): void
    {
        $this->assertSame('A', (new UrlDecodeUniTransform())->apply('%u0041'));
        $this->assertSame("' OR 1=1", (new UrlDecodeUniTransform())->apply("%u0027%20OR%201%3D1"));
    }

    public function testHtmlEntityDecode(): void
    {
        $this->assertSame('<script>', (new HtmlEntityDecodeTransform())->apply('&lt;script&gt;'));
        $this->assertSame("'OR'1", (new HtmlEntityDecodeTransform())->apply('&#39;OR&#39;1'));
    }

    public function testCompressWhitespace(): void
    {
        $this->assertSame('a b c', (new CompressWhitespaceTransform())->apply("a  b\t\tc"));
    }

    public function testRemoveWhitespace(): void
    {
        $this->assertSame('abc', (new RemoveWhitespaceTransform())->apply("a\tb c"));
    }

    public function testRemoveNulls(): void
    {
        $this->assertSame('abc', (new RemoveNullsTransform())->apply("a\0b\0c"));
    }

    public function testLength(): void
    {
        $this->assertSame('5', (new LengthTransform())->apply('hello'));
    }

    public function testBase64Decode(): void
    {
        $this->assertSame('hello', (new Base64DecodeTransform())->apply('aGVsbG8='));
    }

    public function testCmdLine(): void
    {
        $cmdLineTransform = new CmdLineTransform();
        $this->assertSame('cat /etc/passwd', $cmdLineTransform->apply('c\\at "/etc/passwd"'));
        $this->assertSame('ls;cat', $cmdLineTransform->apply('ls ; cat'));
    }

    public function testNormalisePath(): void
    {
        $normalisePathTransform = new NormalisePathTransform();
        $this->assertSame('/etc/passwd', $normalisePathTransform->apply('/etc//passwd'));
        $this->assertSame('/etc/passwd', $normalisePathTransform->apply('/var/../etc/passwd'));
    }

    public function testRemoveComments(): void
    {
        $this->assertSame('SELECTFROM users', (new RemoveCommentsTransform())->apply('SELECT/*foo*/FROM users'));
        $this->assertSame('SELECT ', (new RemoveCommentsTransform())->apply('SELECT -- comment'));
    }

    public function testReplaceComments(): void
    {
        $this->assertSame('SELECT FROM users', (new ReplaceCommentsTransform())->apply('SELECT/*foo*/FROM users'));
    }

    public function testUtf8ToUnicode(): void
    {
        $utf8ToUnicodeTransform = new Utf8ToUnicodeTransform();
        $this->assertSame('abc', $utf8ToUnicodeTransform->apply('abc'));
        $this->assertStringContainsString('%u', $utf8ToUnicodeTransform->apply('café'));
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Operators;

use Kanopi\Crs\Operators\BeginsWithOperator;
use Kanopi\Crs\Operators\ContainsOperator;
use Kanopi\Crs\Operators\EndsWithOperator;
use Kanopi\Crs\Operators\EqOperator;
use Kanopi\Crs\Operators\GtOperator;
use Kanopi\Crs\Operators\IpMatchOperator;
use Kanopi\Crs\Operators\PmOperator;
use Kanopi\Crs\Operators\RxOperator;
use Kanopi\Crs\Operators\StreqOperator;
use Kanopi\Crs\Operators\ValidateByteRangeOperator;
use Kanopi\Crs\Operators\ValidateUrlEncodingOperator;
use Kanopi\Crs\Operators\ValidateUtf8EncodingOperator;
use PHPUnit\Framework\TestCase;

final class OperatorsTest extends TestCase
{
    public function testRxBasic(): void
    {
        $rxOperator = new RxOperator();
        $this->assertTrue($rxOperator->evaluate('(?i)select\s+from', 'SELECT FROM users')->matched);
        $this->assertFalse($rxOperator->evaluate('(?i)select\s+from', 'hello world')->matched);
    }

    public function testRxReturnsMatchedData(): void
    {
        $rxOperator = new RxOperator();
        $operatorMatch = $rxOperator->evaluate('foo\d+', 'abc foo123 xyz');
        $this->assertTrue($operatorMatch->matched);
        $this->assertSame('foo123', $operatorMatch->matchedData);
    }

    public function testRxInvalidPatternMisses(): void
    {
        $rxOperator = new RxOperator();
        $this->assertFalse($rxOperator->evaluate('(unclosed', 'value')->matched);
    }

    public function testPm(): void
    {
        $pmOperator = new PmOperator();
        $this->assertTrue($pmOperator->evaluate('select union insert', 'A select B')->matched);
        $this->assertFalse($pmOperator->evaluate('select union insert', 'nothing here')->matched);
        $this->assertTrue($pmOperator->evaluate('SELECT', 'a select b')->matched);
    }

    public function testBeginsWith(): void
    {
        $this->assertTrue((new BeginsWithOperator())->evaluate('/admin', '/admin/users')->matched);
        $this->assertFalse((new BeginsWithOperator())->evaluate('/admin', '/public')->matched);
    }

    public function testEndsWith(): void
    {
        $this->assertTrue((new EndsWithOperator())->evaluate('.php', '/x/y.php')->matched);
        $this->assertFalse((new EndsWithOperator())->evaluate('.php', '/x/y.html')->matched);
    }

    public function testContains(): void
    {
        $this->assertTrue((new ContainsOperator())->evaluate('admin', '/path/to/admin/x')->matched);
        $this->assertFalse((new ContainsOperator())->evaluate('admin', '/path/to/public')->matched);
    }

    public function testStreq(): void
    {
        $this->assertTrue((new StreqOperator())->evaluate('GET', 'GET')->matched);
        $this->assertFalse((new StreqOperator())->evaluate('GET', 'POST')->matched);
    }

    public function testEqAndGt(): void
    {
        $this->assertTrue((new EqOperator())->evaluate('5', '5')->matched);
        $this->assertTrue((new GtOperator())->evaluate('5', '10')->matched);
        $this->assertFalse((new GtOperator())->evaluate('5', '3')->matched);
    }

    public function testIpMatchSingleAddress(): void
    {
        $ipMatchOperator = new IpMatchOperator();
        $this->assertTrue($ipMatchOperator->evaluate('192.168.1.1', '192.168.1.1')->matched);
        $this->assertFalse($ipMatchOperator->evaluate('192.168.1.1', '192.168.1.2')->matched);
    }

    public function testIpMatchCidr(): void
    {
        $ipMatchOperator = new IpMatchOperator();
        $this->assertTrue($ipMatchOperator->evaluate('10.0.0.0/8', '10.5.5.5')->matched);
        $this->assertFalse($ipMatchOperator->evaluate('10.0.0.0/8', '11.0.0.0')->matched);
        $this->assertTrue($ipMatchOperator->evaluate('10.0.0.0/8, 192.168.0.0/16', '192.168.5.5')->matched);
    }

    public function testValidateByteRange(): void
    {
        $validateByteRangeOperator = new ValidateByteRangeOperator();
        $this->assertFalse($validateByteRangeOperator->evaluate('32-126', 'hello world')->matched);
        $this->assertTrue($validateByteRangeOperator->evaluate('32-126', "hello\x01world")->matched);
    }

    public function testValidateUrlEncoding(): void
    {
        $validateUrlEncodingOperator = new ValidateUrlEncodingOperator();
        $this->assertFalse($validateUrlEncodingOperator->evaluate('', '/foo%20bar')->matched);
        $this->assertTrue($validateUrlEncodingOperator->evaluate('', '/foo%2zbar')->matched);
        $this->assertTrue($validateUrlEncodingOperator->evaluate('', '/foo%2')->matched);
    }

    public function testValidateUtf8Encoding(): void
    {
        $validateUtf8EncodingOperator = new ValidateUtf8EncodingOperator();
        $this->assertFalse($validateUtf8EncodingOperator->evaluate('', 'café')->matched);
        $this->assertTrue($validateUtf8EncodingOperator->evaluate('', "\xC0\xAF")->matched);
    }
}

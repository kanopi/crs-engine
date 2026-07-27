<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Operators;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\Operators\WithinOperator;
use Kanopi\Crs\Runtime\CrsTxDefaults;
use PHPUnit\Framework\TestCase;

/**
 * @within compares complete whitespace-separated entries, not substrings.
 *
 * The substring form let `OST` past tx.allowed_methods (it occurs inside POST)
 * and made an empty value match every list. The delimiter-wrapped lists CRS
 * uses must keep working, so each of the nine shipped usages is pinned here.
 */
final class WithinOperatorTest extends TestCase
{
    private WithinOperator $withinOperator;

    /** @var array<string, string> */
    private array $defaults;

    protected function setUp(): void
    {
        $this->withinOperator = new WithinOperator();
        $this->defaults       = CrsTxDefaults::forConfig(new CrsConfig());
    }

    private function isWithin(string $argument, string $value): bool
    {
        return $this->withinOperator->evaluate($argument, $value)->matched;
    }

    public function testMatchesACompleteEntry(): void
    {
        $this->assertTrue($this->isWithin('GET HEAD POST OPTIONS', 'GET'));
        $this->assertTrue($this->isWithin('GET HEAD POST OPTIONS', 'OPTIONS'));
    }

    public function testRejectsAValueThatIsMerelyASubstringOfAnEntry(): void
    {
        foreach (['OST', 'ET', 'T', 'HEA', 'PTION', 'S'] as $value) {
            $this->assertFalse(
                $this->isWithin('GET HEAD POST OPTIONS', $value),
                sprintf('%s is a substring of the list but not an entry; it must not match.', $value)
            );
        }
    }

    public function testRejectsAnEmptyValue(): void
    {
        $this->assertFalse($this->isWithin('GET HEAD POST OPTIONS', ''));
        $this->assertFalse($this->isWithin('', ''));
    }

    public function testRejectsAValueSpanningTwoEntries(): void
    {
        $this->assertFalse($this->isWithin('GET HEAD POST OPTIONS', 'GET HEAD'));
        $this->assertFalse($this->isWithin('GET HEAD POST OPTIONS', 'D POS'));
    }

    public function testIsCaseSensitive(): void
    {
        $this->assertFalse($this->isWithin('GET HEAD POST OPTIONS', 'get'));
        $this->assertTrue($this->isWithin('utf-8', 'utf-8'));
    }

    public function testToleratesIrregularSpacingInTheList(): void
    {
        $this->assertTrue($this->isWithin("  GET \t HEAD \n POST  ", 'HEAD'));
    }

    public function testEmptyListMatchesNothing(): void
    {
        $this->assertFalse($this->isWithin('', 'GET'));
        $this->assertFalse($this->isWithin('   ', 'GET'));
    }

    // --- the nine shipped usages ---------------------------------------------

    public function testAllowedMethods(): void
    {
        $list = $this->defaults['tx.allowed_methods'];

        foreach (['GET', 'HEAD', 'POST', 'OPTIONS'] as $method) {
            $this->assertTrue($this->isWithin($list, $method), $method . ' should be allowed.');
        }

        foreach (['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'OST', ''] as $method) {
            $this->assertFalse(
                $this->isWithin($list, $method),
                sprintf('%s is not on the allow-list, so 911100 must fire.', $method === '' ? '(empty)' : $method)
            );
        }
    }

    public function testAllowedHttpVersions(): void
    {
        $list = $this->defaults['tx.allowed_http_versions'];

        $this->assertTrue($this->isWithin($list, 'HTTP/1.1'));
        $this->assertTrue($this->isWithin($list, 'HTTP/2'));
        $this->assertFalse($this->isWithin($list, 'HTTP/0.9'));
        $this->assertFalse($this->isWithin($list, 'TTP/1.1'));
    }

    public function testHttp2LiteralListFrom920180(): void
    {
        $list = 'HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0';

        $this->assertTrue($this->isWithin($list, 'HTTP/2.0'));
        $this->assertFalse($this->isWithin($list, 'HTTP/1.1'), 'HTTP/1.1 must not match, so the chain condition fires.');
    }

    public function testAllowedContentTypeUsesPipeWrappedNeedles(): void
    {
        $list = $this->defaults['tx.allowed_request_content_type'];

        // 920420 builds the needle as '|%{tx.0}|'.
        $this->assertTrue($this->isWithin($list, '|application/json|'));
        $this->assertTrue($this->isWithin($list, '|text/plain|'));
        $this->assertFalse($this->isWithin($list, '|application/x-shockwave-flash|'));
        // A partial that the substring form would have accepted.
        $this->assertFalse($this->isWithin($list, '|application/js'));
        $this->assertFalse($this->isWithin($list, 'application/json'));
    }

    public function testAllowedCharsetUsesPipeWrappedNeedles(): void
    {
        $list = $this->defaults['tx.allowed_request_content_type_charset'];

        // 920480 and 922100 both build the needle as '|%{tx.1}|'.
        foreach (['|utf-8|', '|iso-8859-1|', '|iso-8859-15|', '|windows-1252|'] as $needle) {
            $this->assertTrue($this->isWithin($list, $needle), $needle . ' is on the allow-list.');
        }

        $this->assertFalse($this->isWithin($list, '|ibm037|'));
    }

    public function testRestrictedExtensionsUseSlashSuffixedNeedles(): void
    {
        $list = $this->defaults['tx.restricted_extensions'];

        // 920440 builds the needle as '.%{tx.1}/'.
        $this->assertTrue($this->isWithin($list, '.bak/'));
        $this->assertTrue($this->isWithin($list, '.sql/'));
        $this->assertFalse($this->isWithin($list, '.php/'), '.php is not a restricted extension.');
        $this->assertFalse($this->isWithin($list, '.ba'), 'A partial extension must not match.');
    }

    public function testRestrictedHeadersUseSlashWrappedNeedles(): void
    {
        // 920450 / 920451 build the needle as '/%{tx.0}/'.
        $this->assertTrue($this->isWithin($this->defaults['tx.restricted_headers_basic'], '/proxy/'));
        $this->assertTrue($this->isWithin($this->defaults['tx.restricted_headers_basic'], '/lock-token/'));
        $this->assertFalse($this->isWithin($this->defaults['tx.restricted_headers_basic'], '/accept/'));
        $this->assertTrue($this->isWithin($this->defaults['tx.restricted_headers_extended'], '/accept-charset/'));
    }
}

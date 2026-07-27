<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\Exception\ConfigurationException;
use Kanopi\Crs\Runtime\CrsTxDefaults;
use PHPUnit\Framework\TestCase;

/**
 * anomalyThresholds took a four-key array and read two of them, and the two it
 * read were named after CRS severities while actually meaning direction. The
 * keys are now `inbound` and `outbound`; the severity spellings survive as
 * deprecated aliases. Per-severity contributions moved to severityScores,
 * where four severity names actually mean something.
 */
final class CrsConfigTest extends TestCase
{
    /**
     * @param callable(): mixed $callback
     * @return array<int, string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $seen = [];
        set_error_handler(
            static function (int $_errno, string $message) use (&$seen): bool {
                $seen[] = $message;
                return true;
            },
            E_USER_DEPRECATED,
        );

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $seen;
    }

    public function testDefaultsAreDirectional(): void
    {
        $crsConfig = new CrsConfig();

        $this->assertSame(['inbound' => 5, 'outbound' => 4], $crsConfig->anomalyThresholds);
        $this->assertSame(5, $crsConfig->inboundThreshold());
        $this->assertSame(4, $crsConfig->outboundThreshold());
    }

    public function testDirectionalKeysAreAcceptedWithoutDeprecation(): void
    {
        $crsConfig = null;
        $deprecations = $this->collectDeprecations(static function () use (&$crsConfig): void {
            $crsConfig = new CrsConfig(anomalyThresholds: ['inbound' => 7, 'outbound' => 9]);
        });

        $this->assertSame([], $deprecations);
        $this->assertSame(7, $crsConfig?->inboundThreshold());
        $this->assertSame(9, $crsConfig?->outboundThreshold());
    }

    public function testSeveritySpellingsStillWorkAndAreDeprecated(): void
    {
        $crsConfig = null;
        $deprecations = $this->collectDeprecations(static function () use (&$crsConfig): void {
            $crsConfig = new CrsConfig(anomalyThresholds: ['critical' => 7, 'error' => 9]);
        });

        $this->assertSame(7, $crsConfig?->inboundThreshold(), "'critical' set the inbound threshold.");
        $this->assertSame(9, $crsConfig?->outboundThreshold(), "'error' set the outbound threshold.");
        $this->assertCount(2, $deprecations);
    }

    /**
     * The pre-rename default shape. Passing it must not become a hard error —
     * integrators built settings UIs from these key names.
     */
    public function testLegacyFourKeyShapeStillConstructs(): void
    {
        $crsConfig = null;
        $deprecations = $this->collectDeprecations(static function () use (&$crsConfig): void {
            $crsConfig = new CrsConfig(anomalyThresholds: [
                'critical' => 5,
                'error'    => 4,
                'warning'  => 3,
                'notice'   => 2,
            ]);
        });

        $this->assertSame(5, $crsConfig?->inboundThreshold());
        $this->assertSame(4, $crsConfig?->outboundThreshold());
        $this->assertCount(4, $deprecations);
        $this->assertStringContainsString('never had any effect', $deprecations[2]);
    }

    public function testPartialOverrideKeepsTheOtherDefault(): void
    {
        $crsConfig = new CrsConfig(anomalyThresholds: ['inbound' => 20]);

        $this->assertSame(20, $crsConfig->inboundThreshold());
        $this->assertSame(4, $crsConfig->outboundThreshold());
    }

    public function testUnknownThresholdKeyIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage("Unknown anomaly threshold key 'inbund'");

        new CrsConfig(anomalyThresholds: ['inbund' => 5]);
    }

    public function testSeverityScoresDefaultToCrsValues(): void
    {
        $crsConfig = new CrsConfig();

        $this->assertSame(5, $crsConfig->severityScore('critical'));
        $this->assertSame(4, $crsConfig->severityScore('error'));
        $this->assertSame(3, $crsConfig->severityScore('warning'));
        $this->assertSame(2, $crsConfig->severityScore('notice'));
    }

    public function testSeverityScoresAreOverridableAndPartial(): void
    {
        $crsConfig = new CrsConfig(severityScores: ['critical' => 10]);

        $this->assertSame(10, $crsConfig->severityScore('critical'));
        $this->assertSame(4, $crsConfig->severityScore('error'));
    }

    public function testUnknownSeverityIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage("Unknown severity 'catastrophic'");

        new CrsConfig(severityScores: ['catastrophic' => 1]);
    }

    public function testSeverityScoreOfAnUnknownSeverityIsZero(): void
    {
        $this->assertSame(0, (new CrsConfig())->severityScore('nonexistent'));
    }

    public function testThresholdsReachTheTxSeedValues(): void
    {
        $defaults = CrsTxDefaults::forConfig(
            new CrsConfig(anomalyThresholds: ['inbound' => 11, 'outbound' => 13]),
        );

        $this->assertSame('11', $defaults['tx.inbound_anomaly_score_threshold']);
        $this->assertSame('13', $defaults['tx.outbound_anomaly_score_threshold']);
    }

    public function testSeverityScoresReachTheTxSeedValues(): void
    {
        $defaults = CrsTxDefaults::forConfig(
            new CrsConfig(severityScores: ['critical' => 8, 'notice' => 1]),
        );

        $this->assertSame('8', $defaults['tx.critical_anomaly_score']);
        $this->assertSame('1', $defaults['tx.notice_anomaly_score']);
        $this->assertSame('4', $defaults['tx.error_anomaly_score']);
    }

    public function testFromArraySupportsBothNewKeys(): void
    {
        $crsConfig = CrsConfig::fromArray([
            'anomaly_thresholds' => ['inbound' => 15, 'outbound' => 6],
            'severity_scores'    => ['critical' => 7],
        ]);

        $this->assertSame(15, $crsConfig->inboundThreshold());
        $this->assertSame(6, $crsConfig->outboundThreshold());
        $this->assertSame(7, $crsConfig->severityScore('critical'));
    }

    public function testFromArrayDefaultsAreDirectional(): void
    {
        $crsConfig = CrsConfig::fromArray([]);

        $this->assertSame(['inbound' => 5, 'outbound' => 4], $crsConfig->anomalyThresholds);
    }

    public function testKeysAreCaseInsensitive(): void
    {
        $crsConfig = new CrsConfig(anomalyThresholds: ['INBOUND' => 12]);

        $this->assertSame(12, $crsConfig->inboundThreshold());
    }

    public function testInspectionLimitsDefaultToTheDocumentedValues(): void
    {
        $crsConfig = new CrsConfig();

        $this->assertSame(CrsConfig::DEFAULT_MAX_ARGS, $crsConfig->maxArgs);
        $this->assertSame(CrsConfig::DEFAULT_MAX_BODY_BYTES, $crsConfig->maxBodyBytes);
        $this->assertSame(CrsConfig::DEFAULT_MAX_ARG_BYTES, $crsConfig->maxArgBytes);
    }

    public function testUnlimitedIsAnAcceptedInspectionLimit(): void
    {
        $crsConfig = new CrsConfig(
            maxArgs: CrsConfig::UNLIMITED,
            maxBodyBytes: CrsConfig::UNLIMITED,
            maxArgBytes: CrsConfig::UNLIMITED,
        );

        $this->assertSame(CrsConfig::UNLIMITED, $crsConfig->maxArgs);
        $this->assertSame(CrsConfig::UNLIMITED, $crsConfig->maxBodyBytes);
        $this->assertSame(CrsConfig::UNLIMITED, $crsConfig->maxArgBytes);
    }

    /**
     * Zero would mean "inspect nothing", which is a WAF that does not work, and
     * is the shape an unset config key would arrive in.
     */
    public function testZeroInspectionLimitIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        new CrsConfig(maxArgs: 0);
    }

    public function testNegativeInspectionLimitOtherThanUnlimitedIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        new CrsConfig(maxBodyBytes: -99);
    }

    public function testInspectionLimitsComeThroughFromArray(): void
    {
        $crsConfig = CrsConfig::fromArray([
            'max_args'       => 10,
            'max_body_bytes' => 20,
            'max_arg_bytes'  => 30,
        ]);

        $this->assertSame(10, $crsConfig->maxArgs);
        $this->assertSame(20, $crsConfig->maxBodyBytes);
        $this->assertSame(30, $crsConfig->maxArgBytes);
    }

    public function testFailClosedOnOperatorErrorDefaultsOffAndComesThroughFromArray(): void
    {
        $this->assertFalse((new CrsConfig())->failClosedOnOperatorError);
        $this->assertTrue(CrsConfig::fromArray(['fail_closed_on_operator_error' => true])->failClosedOnOperatorError);
    }
}

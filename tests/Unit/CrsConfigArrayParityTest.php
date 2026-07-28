<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit;

use Kanopi\Crs\CrsConfig;
use PHPUnit\Framework\TestCase;

/**
 * Every constructor parameter must be reachable through fromArray().
 *
 * That is the path the intended consumers actually take: a Drupal module hands
 * fromArray() the result of config.get(), a WordPress plugin hands it
 * get_option(). A parameter with no wire key is invisible to both — settable
 * only by an integrator constructing the object by hand, which the config-driven
 * ones are not doing.
 *
 * The map below is also the documented wire format. Adding a constructor
 * parameter without adding it here fails, which is the point: after 1.0 the
 * signature is frozen and a missing key is a gap someone has to live with.
 */
final class CrsConfigArrayParityTest extends TestCase
{
    /**
     * Wire key => [value to send, property to read, value expected on the object].
     *
     * Values are deliberately non-default, so a key that is accepted but
     * ignored fails rather than coincidentally matching.
     *
     * @return array<string, array{mixed, string, mixed}>
     */
    private function wireFormat(): array
    {
        return [
            'paranoia'                      => [3, 'paranoia', 3],
            'mode'                          => [CrsConfig::MODE_MONITOR, 'mode', CrsConfig::MODE_MONITOR],
            'request_mode'                  => [CrsConfig::MODE_MONITOR, 'requestMode', CrsConfig::MODE_MONITOR],
            'response_mode'                 => [CrsConfig::MODE_BLOCK, 'responseMode', CrsConfig::MODE_BLOCK],
            'anomaly_thresholds'            => [['inbound' => 11, 'outbound' => 12], 'anomalyThresholds', ['inbound' => 11, 'outbound' => 12]],
            'severity_scores'               => [['critical' => 9], 'severityScores', ['critical' => 9, 'error' => 4, 'warning' => 3, 'notice' => 2]],
            'disabled_rules'                => [[920540], 'disabledRules', [920540]],
            'disabled_categories'           => [['xss'], 'disabledCategories', ['xss']],
            'rules_path'                    => ['/tmp/rules', 'rulesPath', '/tmp/rules'],
            'fail_closed_on_operator_error' => [true, 'failClosedOnOperatorError', true],
            'max_args'                      => [77, 'maxArgs', 77],
            'max_arg_bytes'                 => [7777, 'maxArgBytes', 7777],
            'max_request_body_bytes'        => [8888, 'maxRequestBodyBytes', 8888],
            'max_response_body_bytes'       => [9999, 'maxResponseBodyBytes', 9999],
        ];
    }

    public function testEveryConstructorParameterHasAWireKey(): void
    {
        $parameters = (new \ReflectionMethod(CrsConfig::class, '__construct'))->getParameters();

        $missing = [];
        foreach ($parameters as $parameter) {
            $snake = strtolower((string) preg_replace('/([a-z])([A-Z])/', '$1_$2', $parameter->getName()));
            if (!array_key_exists($snake, $this->wireFormat())) {
                $missing[] = $parameter->getName() . ' (expected key: ' . $snake . ')';
            }
        }

        $this->assertSame(
            [],
            $missing,
            "Constructor parameters with no fromArray() key.\nA config-driven integrator cannot set these:\n  "
            . implode("\n  ", $missing)
        );
    }

    public function testEveryWireKeyActuallyReachesItsProperty(): void
    {
        foreach ($this->wireFormat() as $key => [$send, $property, $expected]) {
            $crsConfig = CrsConfig::fromArray([$key => $send]);

            $this->assertSame(
                $expected,
                $crsConfig->{$property},
                sprintf("fromArray() accepted '%s' but it did not reach \$%s.", $key, $property)
            );
        }
    }

    public function testTheWireFormatHasNoKeysThatDoNotExist(): void
    {
        $names = array_map(
            static fn (\ReflectionParameter $reflectionParameter): string => strtolower((string) preg_replace('/([a-z])([A-Z])/', '$1_$2', $reflectionParameter->getName())),
            (new \ReflectionMethod(CrsConfig::class, '__construct'))->getParameters(),
        );

        $stale = array_diff(array_keys($this->wireFormat()), $names);

        $this->assertSame([], $stale, 'This map documents keys the constructor no longer has: ' . implode(', ', $stale));
    }

    /**
     * Unknown keys are ignored rather than rejected, because the common CMS
     * shape is handing over a whole settings array that carries unrelated keys
     * alongside the engine's. Pinned so the leniency is a decision rather than
     * an accident — and so anyone tempted to make it strict sees the reason.
     */
    public function testUnknownKeysAreIgnored(): void
    {
        $crsConfig = CrsConfig::fromArray([
            'paranoia'            => 2,
            'some_other_module'   => ['not' => 'ours'],
            'max_body_bytes_typo' => 1,
        ]);

        $this->assertSame(2, $crsConfig->paranoia);
    }

    public function testAnEmptyArrayGivesTheDocumentedDefaults(): void
    {
        $fromArray = CrsConfig::fromArray([]);
        $crsConfig    = new CrsConfig();

        $this->assertEquals($crsConfig, $fromArray, 'fromArray([]) and new CrsConfig() must agree.');
    }
}

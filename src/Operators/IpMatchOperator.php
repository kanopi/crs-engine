<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

/**
 * @ipMatch — argument is a comma-separated list of IPv4/IPv6 addresses or
 * CIDR ranges. Match if $value (an IP address) falls within any of them.
 */
final class IpMatchOperator implements OperatorInterface
{
    /** @var array<string, array<int, array{0:string,1:int}>> */
    private static array $parsedCache = [];

    public function name(): string
    {
        return 'ipMatch';
    }

    public function evaluate(string $argument, string $value): OperatorMatch
    {
        $ranges = self::$parsedCache[$argument] ?? null;
        if ($ranges === null) {
            $ranges = [];
            foreach (preg_split('/[\s,]+/', trim($argument)) ?: [] as $entry) {
                if ($entry === '') {
                    continue;
                }

                if (str_contains($entry, '/')) {
                    [$ip, $bits] = explode('/', $entry, 2);
                    $ranges[] = [$ip, (int) $bits];
                } else {
                    $ranges[] = [$entry, str_contains($entry, ':') ? 128 : 32];
                }
            }

            self::$parsedCache[$argument] = $ranges;
        }

        $valueBin = @inet_pton($value);
        if ($valueBin === false) {
            return OperatorMatch::miss();
        }

        foreach ($ranges as [$ip, $bits]) {
            $ipBin = @inet_pton($ip);
            if ($ipBin === false) {
                continue;
            }

            if (strlen($ipBin) !== strlen($valueBin)) {
                continue;
            }

            if ($this->binaryMatch($ipBin, $valueBin, $bits)) {
                return OperatorMatch::hit($ip . '/' . $bits);
            }
        }

        return OperatorMatch::miss();
    }

    private function binaryMatch(string $a, string $b, int $bits): bool
    {
        $bytes = intdiv($bits, 8);
        if ($bytes > 0 && substr($a, 0, $bytes) !== substr($b, 0, $bytes)) {
            return false;
        }

        $remaining = $bits % 8;
        if ($remaining === 0) {
            return true;
        }

        $mask = ~((1 << (8 - $remaining)) - 1) & 0xff;
        return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
    }
}

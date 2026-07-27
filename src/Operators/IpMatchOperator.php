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

                $width = str_contains($entry, ':') ? 128 : 32;

                if (!str_contains($entry, '/')) {
                    $ranges[] = [$entry, $width];
                    continue;
                }

                [$ip, $bitsRaw] = explode('/', $entry, 2);
                $bitsRaw = trim($bitsRaw);
                // A malformed prefix is a typo in the rule, and the handling has
                // to be chosen so that a typo can never *widen* a range — a
                // deny-list entry that quietly becomes match-all is far worse
                // than one that stops matching.
                //
                // Anything not a plain non-negative integer is dropped —
                // ctype_digit() rejects '', '-1', '+24', '24.5' and 'abc' alike.
                // Casting instead would send all of them to 0, and a zero prefix
                // masks nothing, so every one would match every address in the
                // family.
                if (!ctype_digit($bitsRaw)) {
                    continue;
                }

                // Too-large is clamped rather than dropped: /33 on IPv4 can only
                // have meant "this exact address", and clamping to the address
                // width narrows, so it is safe. Unclamped it indexed past the
                // end of the packed address and raised an uncaught Error.
                $ranges[] = [$ip, min((int) $bitsRaw, $width)];
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

        // Callers clamp $bits to the address width, so this should be
        // unreachable. Kept because the alternative when it is not is an
        // uncaught Error out of the middle of request evaluation.
        if (!isset($a[$bytes], $b[$bytes])) {
            return true;
        }

        $mask = ~((1 << (8 - $remaining)) - 1) & 0xff;
        return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
    }
}

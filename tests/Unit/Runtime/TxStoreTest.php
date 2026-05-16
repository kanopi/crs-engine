<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Unit\Runtime;

use Kanopi\Crs\Runtime\TxStore;
use PHPUnit\Framework\TestCase;

final class TxStoreTest extends TestCase
{
    public function testSetAndGet(): void
    {
        $txStore = new TxStore();
        $txStore->set('foo', 'bar');
        $this->assertSame('bar', $txStore->get('foo'));
        $this->assertSame('bar', $txStore->get('FOO'));
    }

    public function testIncrementStartsFromZero(): void
    {
        $txStore = new TxStore();
        $txStore->increment('counter', 5);
        $this->assertSame(5, $txStore->getInt('counter'));
        $txStore->increment('counter', 3);
        $this->assertSame(8, $txStore->getInt('counter'));
    }

    public function testDecrement(): void
    {
        $txStore = new TxStore();
        $txStore->set('counter', '10');
        $txStore->decrement('counter', 4);
        $this->assertSame(6, $txStore->getInt('counter'));
    }

    public function testUnset(): void
    {
        $txStore = new TxStore();
        $txStore->set('foo', 'bar');
        $txStore->unset('foo');
        $this->assertFalse($txStore->has('foo'));
    }
}

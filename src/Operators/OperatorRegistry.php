<?php

declare(strict_types=1);

namespace Kanopi\Crs\Operators;

use Kanopi\Crs\Exception\CrsEngineException;

final class OperatorRegistry
{
    /** @var array<string, OperatorInterface> */
    private array $operators = [];

    public function __construct()
    {
        $this->registerDefaults();
    }

    public function register(OperatorInterface $operator): void
    {
        $this->operators[strtolower($operator->name())] = $operator;
    }

    public function get(string $name): OperatorInterface
    {
        $key = strtolower($name);
        if (!isset($this->operators[$key])) {
            throw new CrsEngineException('Unknown operator: @' . $name);
        }

        return $this->operators[$key];
    }

    public function has(string $name): bool
    {
        return isset($this->operators[strtolower($name)]);
    }

    private function registerDefaults(): void
    {
        $this->register(new RxOperator());
        $this->register(new PmOperator());
        $this->register(new PmfOperator());
        $this->register(new BeginsWithOperator());
        $this->register(new EndsWithOperator());
        $this->register(new ContainsOperator());
        $this->register(new ContainsWordOperator());
        $this->register(new StreqOperator());
        $this->register(new EqOperator());
        $this->register(new GtOperator());
        $this->register(new LtOperator());
        $this->register(new GeOperator());
        $this->register(new LeOperator());
        $this->register(new WithinOperator());
        $this->register(new IpMatchOperator());
        $this->register(new ValidateByteRangeOperator());
        $this->register(new ValidateUrlEncodingOperator());
        $this->register(new ValidateUtf8EncodingOperator());
    }
}

<?php

declare(strict_types=1);

namespace Kanopi\Crs\Transforms;

use Kanopi\Crs\Exception\CrsEngineException;

final class TransformRegistry
{
    /** @var array<string, TransformInterface> */
    private array $transforms = [];

    public function __construct()
    {
        $this->registerDefaults();
    }

    public function register(TransformInterface $transform): void
    {
        $this->transforms[strtolower($transform->name())] = $transform;
    }

    /**
     * Reach one transform under a second name.
     *
     * Used for spelling: CRS writes `normalizePath`, this project's own docs
     * and tests grew up on `normalisePath`, and both should resolve.
     */
    public function alias(string $alias, string $existing): void
    {
        $this->transforms[strtolower($alias)] = $this->get($existing);
    }

    public function get(string $name): TransformInterface
    {
        $key = strtolower($name);
        if (!isset($this->transforms[$key])) {
            throw new CrsEngineException('Unknown transform: t:' . $name);
        }

        return $this->transforms[$key];
    }

    public function has(string $name): bool
    {
        return isset($this->transforms[strtolower($name)]);
    }

    private function registerDefaults(): void
    {
        $this->register(new NoneTransform());
        $this->register(new LowercaseTransform());
        $this->register(new UppercaseTransform());
        $this->register(new UrlDecodeTransform());
        $this->register(new UrlDecodeUniTransform());
        $this->register(new HtmlEntityDecodeTransform());
        $this->register(new CompressWhitespaceTransform());
        $this->register(new RemoveWhitespaceTransform());
        $this->register(new ReplaceNullsTransform());
        $this->register(new RemoveNullsTransform());
        $this->register(new Utf8ToUnicodeTransform());
        $this->register(new Base64DecodeTransform());
        $this->register(new Base64DecodeExtTransform());
        $this->register(new CmdLineTransform());
        $this->register(new NormalisePathTransform());
        $this->alias('normalisePath', 'normalizePath');
        $this->register(new NormalizePathWinTransform());
        $this->register(new JsDecodeTransform());
        $this->register(new CssDecodeTransform());
        $this->register(new EscapeSeqDecodeTransform());
        $this->register(new RemoveCommentsCharTransform());
        $this->register(new LengthTransform());
        $this->register(new Sha1Transform());
        $this->register(new Md5Transform());
        $this->register(new TrimTransform());
        $this->register(new RemoveCommentsTransform());
        $this->register(new ReplaceCommentsTransform());
    }
}

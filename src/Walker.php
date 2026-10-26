<?php

declare(strict_types=1);

namespace Ghostchars;

final class Walker
{
    private const MAX_BYTES = 2_000_000;

    /** @var array<string, true> */
    private const SKIP_DIRS = [
        'vendor' => true,
        'node_modules' => true,
        '.git' => true,
        '.idea' => true,
        '.vscode' => true,
    ];

    /** @var array<string, true> */
    private const EXTS = [
        'php' => true, 'phtml' => true, 'inc' => true, 'phpt' => true, 'twig' => true,
        'json' => true, 'yml' => true, 'yaml' => true, 'xml' => true, 'env' => true,
        'ini' => true, 'js' => true, 'jsx' => true, 'ts' => true, 'tsx' => true,
        'mjs' => true, 'cjs' => true, 'vue' => true, 'css' => true, 'scss' => true,
        'html' => true, 'htm' => true, 'sql' => true, 'sh' => true, 'bash' => true,
        'zsh' => true,
    ];

    /**
     * @param list<string> $paths
     * @return list<string>
     */
    public function collect(array $paths): array
    {
        $files = [];
        foreach ($paths as $path) {
            if (is_dir($path)) {
                $this->walk($path, $files, false);
                continue;
            }
            if (is_file($path)) {
                $files[] = $path;
            }
        }
        $files = array_values(array_unique($files));
        sort($files);
        return $files;
    }

    /**
     * @param list<string> $files
     */
    private function walk(string $dir, array &$files, bool $explicit): void
    {
        $iterator = new \DirectoryIterator($dir);
        $nested = [];
        foreach ($iterator as $item) {
            if ($item->isDot() || $item->isLink()) {
                continue;
            }
            $path = $item->getPathname();
            if ($item->isDir()) {
                if (isset(self::SKIP_DIRS[$item->getFilename()])) {
                    continue;
                }
                $nested[] = $path;
                continue;
            }
            if (!$item->isFile()) {
                continue;
            }
            if (!$explicit && !$this->wanted($item->getFilename())) {
                continue;
            }
            $files[] = $path;
        }
        sort($nested);
        foreach ($nested as $path) {
            $this->walk($path, $files, $explicit);
        }
    }

    public function wanted(string $filename): bool
    {
        if ($filename === '.env' || str_starts_with($filename, '.env.')) {
            return true;
        }
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        return isset(self::EXTS[$ext]);
    }

    public function readable(string $path): ?string
    {
        if (!is_file($path)) {
            return 'not a file: ' . $path;
        }
        $size = filesize($path);
        if ($size === false) {
            return 'cannot stat: ' . $path;
        }
        if ($size > self::MAX_BYTES) {
            return null;
        }
        $head = file_get_contents($path, false, null, 0, 8192);
        if ($head === false) {
            return 'cannot read: ' . $path;
        }
        if (str_contains($head, "\0")) {
            return null;
        }
        return '';
    }
}

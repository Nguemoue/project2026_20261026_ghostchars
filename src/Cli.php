<?php

declare(strict_types=1);

namespace Ghostchars;

final class Cli
{
    /** @param list<string> $argv */
    public static function main(array $argv): int
    {
        $cmd = $argv[1] ?? 'help';

        return match ($cmd) {
            'demo' => self::demo(),
            'scan' => self::scan(array_slice($argv, 2)),
            'fix' => self::fix(array_slice($argv, 2)),
            'help', '-h', '--help' => self::help(0),
            default => self::help(2, 'unknown command: ' . $cmd),
        };
    }

    public static function demo(): int
    {
        $left = 'admin';
        $right = "\u{0430}dmin";
        $name = "save\u{200B}User";
        $visible = preg_replace('/\p{Cf}/u', '', $name);
        if (!is_string($visible)) {
            $visible = 'saveUser';
        }

        $sample = Samples::dirty();
        $findings = (new Scanner())->scan($sample, '<demo>');

        echo "ghostchars  the character the diff does not show\n\n";
        echo $left . ' === ' . $right . "\n";
        echo '  left    ' . Utf8::format(self::firstCp($left)) . " LATIN SMALL LETTER A\n";
        echo '  right   ' . Utf8::format(self::firstCp($right)) . " CYRILLIC SMALL LETTER A\n";
        echo '  php     ' . ($left === $right ? 'equal' : 'NOT equal') . "\n";
        echo "  a review reads both as admin\n\n";
        echo "function name save + zero-width space + User\n";
        echo '  bytes    ' . strlen($name) . "\n";
        echo '  chars    ' . self::charCount($name) . "\n";
        echo '  you see  ' . self::charCount($visible) . "\n\n";
        echo "U+202E inside a string is valid PHP. A reviewer can read the other order.\n";
        echo "Trojan Source, CVE-2021-42574.\n\n";
        echo self::render($findings);
        echo "\nfix strips bidi, invisibles, exotic spaces and curly quotes.\n";
        echo "It does not rewrite the cyrillic a. That is a different letter.\n";
        echo "Nothing is uploaded.\n";

        return 0;
    }

    /** @param list<string> $args */
    public static function scan(array $args): int
    {
        $opt = self::options($args);
        if ($opt['error'] !== null) {
            return self::help(2, $opt['error']);
        }
        if ($opt['help']) {
            return self::help(0);
        }
        if (!isset(self::ranks()[$opt['fail']])) {
            return self::help(2, 'fail-on must be critical, high, medium or none');
        }
        if ($opt['paths'] === []) {
            return self::help(2, 'scan needs a path, or - for stdin');
        }

        $loaded = self::load($opt['paths']);
        if ($loaded['error'] !== null) {
            fwrite(STDERR, "ghostchars: " . $loaded['error'] . "\n");
            return 2;
        }

        $findings = [];
        foreach ($loaded['files'] as $file => $content) {
            foreach ((new Scanner())->scan($content, $file) as $finding) {
                $findings[] = $finding;
            }
        }

        $failed = self::fails($findings, $opt['fail']);
        if ($opt['json']) {
            echo self::json($findings, $failed);
        } else {
            echo self::render($findings);
        }

        return $failed ? 1 : 0;
    }

    /** @param list<string> $args */
    public static function fix(array $args): int
    {
        $opt = self::options($args);
        if ($opt['error'] !== null) {
            return self::help(2, $opt['error']);
        }
        if ($opt['help']) {
            return self::help(0);
        }

        $paths = $opt['paths'];
        if ($paths === []) {
            $paths = ['-'];
        }
        if ($opt['write'] && in_array('-', $paths, true)) {
            fwrite(STDERR, "ghostchars: --write cannot read stdin\n");
            return 2;
        }
        if (!$opt['write'] && count($paths) > 1) {
            fwrite(STDERR, "ghostchars: pass one file to print, or --write for many\n");
            return 2;
        }

        $loaded = self::load($paths);
        if ($loaded['error'] !== null) {
            fwrite(STDERR, "ghostchars: " . $loaded['error'] . "\n");
            return 2;
        }
        if ($loaded['files'] === []) {
            fwrite(STDERR, "ghostchars: nothing to fix\n");
            return 2;
        }

        $fixer = new Fixer();
        $scanner = new Scanner();
        $report = [];

        foreach ($loaded['files'] as $file => $content) {
            [$clean, $edits] = $fixer->fix($content);
            $findingCount = count($scanner->scan($content, $file));
            if ($opt['write']) {
                if ($edits > 0 && file_put_contents($file, $clean) === false) {
                    fwrite(STDERR, "ghostchars: cannot write {$file}\n");
                    return 2;
                }
            } elseif (!$opt['json']) {
                echo $clean;
            }
            $report[] = [
                'file' => $file,
                'edits' => $edits,
                'findings' => $findingCount,
            ];
        }

        if ($opt['json']) {
            $payload = ['files' => $report];
            if (!$opt['write'] && count($report) === 1) {
                $only = array_key_first($loaded['files']);
                $payload['content'] = $fixer->fix($loaded['files'][$only])[0];
            }
            echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
            return 0;
        }

        if ($opt['write']) {
            foreach ($report as $row) {
                echo 'ghostchars  ' . ($row['edits'] === 0 ? 'unchanged' : 'fixed')
                    . '  ' . $row['file'] . '  edits ' . $row['edits'] . "\n";
            }
        }

        return 0;
    }

    /**
     * @param list<string> $args
     * @return array{json:bool, write:bool, fail:string, help:bool, error:?string, paths:list<string>}
     */
    private static function options(array $args): array
    {
        $opt = [
            'json' => false,
            'write' => false,
            'fail' => 'high',
            'help' => false,
            'error' => null,
            'paths' => [],
        ];

        foreach ($args as $arg) {
            if ($arg === '--json') {
                $opt['json'] = true;
            } elseif ($arg === '--write') {
                $opt['write'] = true;
            } elseif ($arg === '--help' || $arg === '-h') {
                $opt['help'] = true;
            } elseif (str_starts_with($arg, '--fail-on=')) {
                $opt['fail'] = substr($arg, strlen('--fail-on='));
            } elseif (str_starts_with($arg, '-') && $arg !== '-') {
                $opt['error'] = 'unknown option: ' . $arg;
            } else {
                $opt['paths'][] = $arg;
            }
        }

        return $opt;
    }

    /**
     * @param list<string> $paths
     * @return array{error:?string, files:array<string, string>}
     */
    private static function load(array $paths): array
    {
        foreach ($paths as $path) {
            if ($path === '-') {
                continue;
            }
            if (!file_exists($path)) {
                return ['error' => 'not found: ' . $path, 'files' => []];
            }
        }

        $walker = new Walker();
        $list = [];
        foreach ($paths as $path) {
            if ($path === '-') {
                $list['-'] = '-';
                continue;
            }
            if (is_dir($path)) {
                foreach ($walker->collect([$path]) as $file) {
                    $list[$file] = $file;
                }
                continue;
            }
            $list[$path] = $path;
        }

        $files = [];
        foreach ($list as $file) {
            if ($file === '-') {
                $stdin = stream_get_contents(STDIN);
                if ($stdin === false) {
                    return ['error' => 'cannot read stdin', 'files' => []];
                }
                $files['stdin'] = $stdin;
                continue;
            }

            $gate = $walker->readable($file);
            if ($gate === null) {
                continue;
            }
            if ($gate !== '') {
                return ['error' => $gate, 'files' => []];
            }
            $content = file_get_contents($file);
            if ($content === false) {
                return ['error' => 'cannot read: ' . $file, 'files' => []];
            }
            $files[$file] = $content;
        }

        return ['error' => null, 'files' => $files];
    }

    /** @param list<array<string, mixed>> $findings */
    public static function fails(array $findings, string $level): bool
    {
        $rank = self::ranks();
        $threshold = $rank[$level] ?? 2;
        if ($threshold === 0) {
            return false;
        }
        foreach ($findings as $finding) {
            $severity = $rank[$finding['severity']] ?? 0;
            if ($severity >= $threshold) {
                return true;
            }
        }
        return false;
    }

    /** @param list<array<string, mixed>> $findings */
    public static function render(array $findings): string
    {
        $buf = '';
        foreach ($findings as $f) {
            $buf .= $f['file'] . ':' . $f['line'] . ':' . $f['column']
                . '  ' . $f['severity'] . '  ' . $f['kind']
                . '  ' . $f['codepoint'] . '  ' . $f['name'] . "\n";
            $buf .= '  ' . $f['message'] . "\n";
            $buf .= '  ' . $f['snippet'] . "\n\n";
        }
        $counts = self::counts($findings);
        $buf .= 'ghostchars  ' . count($findings) . ' findings'
            . '  critical ' . $counts['critical']
            . '  high ' . $counts['high']
            . '  medium ' . $counts['medium'] . "\n";
        return $buf;
    }

    /** @param list<array<string, mixed>> $findings */
    private static function json(array $findings, bool $failed): string
    {
        return json_encode(
            [
                'failed' => $failed,
                'counts' => self::counts($findings),
                'findings' => $findings,
            ],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
        ) . "\n";
    }

    /**
     * @param list<array<string, mixed>> $findings
     * @return array{critical:int, high:int, medium:int}
     */
    private static function counts(array $findings): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0];
        foreach ($findings as $finding) {
            $severity = $finding['severity'];
            if (isset($counts[$severity])) {
                $counts[$severity]++;
            }
        }
        return $counts;
    }

    /** @return array<string, int> */
    private static function ranks(): array
    {
        return ['none' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3];
    }

    private static function firstCp(string $text): int
    {
        $chars = Utf8::decode($text);
        return (int) ($chars[0]['cp'] ?? 0);
    }

    private static function charCount(string $text): int
    {
        $n = 0;
        foreach (Utf8::decode($text) as $ch) {
            if (!$ch['nl']) {
                $n++;
            }
        }
        return $n;
    }

    private static function help(int $code, string $error = ''): int
    {
        if ($error !== '') {
            fwrite(STDERR, "ghostchars: {$error}\n");
        }
        $out = $code === 0 ? STDOUT : STDERR;
        fwrite($out, <<<TXT
ghostchars  the character the diff does not show

Usage:
  php ghostchars.php demo
  php ghostchars.php scan [--json] [--fail-on=high|medium|none] [path...]
  php ghostchars.php fix [--write] [--json] [path...]

scan reads files or directories. php, js, json, yaml, vue, twig, sql, ...
Directories skip vendor, node_modules and .git. stdin is a lone dash:

  php ghostchars.php scan -

fix removes bidi marks, invisible characters, exotic spaces and curly quotes.
It keeps emoji joiners, and it does not rewrite lookalike letters.
One file, or stdin, is printed. --write rewrites files in place.

Exit 0 when nothing at or above --fail-on is found (default: high).
Exit 1 when scan finds some. Exit 2 on usage errors.
A line that contains ghostchars:ignore is skipped.

TXT);
        return $code;
    }
}

<?php

declare(strict_types=1);

namespace Ghostchars;

final class Scanner
{
    /**
     * @return list<array{
     *   file:string, line:int, column:int, byte:int, severity:string, kind:string,
     *   codepoint:string, name:string, message:string, snippet:string
     * }>
     */
    public function scan(string $content, string $file = 'stdin'): array
    {
        $chars = Utf8::decode($content);
        $ignored = $this->ignoredLines($content);
        $findings = [];

        $count = count($chars);
        for ($i = 0; $i < $count; $i++) {
            $ch = $chars[$i];
            if ($ch['nl'] || isset($ignored[$ch['line']])) {
                continue;
            }

            if ($ch['invalid']) {
                $findings[] = $this->finding(
                    $file,
                    $ch,
                    'critical',
                    'utf8',
                    'INVALID UTF-8',
                    'Invalid UTF-8 byte 0x' . strtoupper(dechex($ch['cp'])) . '. The rest of the line is not trustworthy.',
                    $chars,
                    $i,
                );
                continue;
            }

            $apostrophe = $this->isApostrophe($chars, $i);
            $class = Catalog::classify($ch['cp'], $ch['byte'], $apostrophe);
            if ($class === null) {
                continue;
            }

            $findings[] = $this->finding(
                $file,
                $ch,
                $class['severity'],
                $class['kind'],
                $class['name'],
                $class['message'],
                $chars,
                $i,
            );
        }

        foreach ($this->homoglyphs($chars, $ignored) as $hit) {
            $findings[] = $hit($file);
        }

        usort($findings, static function (array $a, array $b): int {
            return [$a['line'], $a['column'], $a['codepoint']] <=> [$b['line'], $b['column'], $b['codepoint']];
        });

        return $findings;
    }

    /**
     * @param list<array{cp:int,ch:string,byte:int,len:int,line:int,column:int,invalid:bool,nl:bool}> $chars
     * @param array<int, true> $ignored
     * @return list<\Closure(string): array<string, mixed>>
     */
    private function homoglyphs(array $chars, array $ignored): array
    {
        $hits = [];
        $count = count($chars);
        $i = 0;

        while ($i < $count) {
            $ch = $chars[$i];
            if ($ch['nl'] || $ch['invalid'] || !Catalog::isIdentByte($ch['cp'])) {
                $i++;
                continue;
            }

            $start = $i;
            $line = $ch['line'];
            $i++;
            while (
                $i < $count
                && !$chars[$i]['nl']
                && !$chars[$i]['invalid']
                && $chars[$i]['line'] === $line
                && Catalog::isIdentByte($chars[$i]['cp'])
            ) {
                $i++;
            }

            if (isset($ignored[$line])) {
                continue;
            }

            $skeleton = '';
            $ascii = 0;
            $conf = [];
            for ($k = $start; $k < $i; $k++) {
                $meta = Catalog::confusable($chars[$k]['cp']);
                if ($meta !== null) {
                    $skeleton .= $meta[0];
                    $conf[] = [$k, $meta];
                } else {
                    $skeleton .= $chars[$k]['ch'];
                    if (Catalog::isAsciiLetter($chars[$k]['cp'])) {
                        $ascii++;
                    }
                }
            }

            if ($conf === []) {
                continue;
            }

            $mixed = $ascii > 0;
            $keyword = Catalog::isKeyword($skeleton);
            $sigil = str_contains($skeleton, '$');
            if (!$mixed && !$keyword && !$sigil) {
                continue;
            }

            foreach ($conf as [$k, $meta]) {
                $looks = $meta[0];
                if ($keyword && !$mixed) {
                    $message = 'Whole token is a lookalike of "' . $skeleton . '". Not the ASCII letters a review reads.';
                } else {
                    $message = 'Looks like "' . $looks . '" (' . Utf8::format(ord($looks)) . '). Token skeletons to "' . $skeleton . '".';
                }
                $hits[] = function (string $file) use ($chars, $k, $meta, $message): array {
                    return $this->finding(
                        $file,
                        $chars[$k],
                        'high',
                        'homoglyph',
                        $meta[1],
                        $message,
                        $chars,
                        $k,
                    );
                };
            }
        }

        return $hits;
    }

    /**
     * @param array<string, mixed> $ch
     * @param list<array<string, mixed>> $chars
     * @return array<string, mixed>
     */
    private function finding(
        string $file,
        array $ch,
        string $severity,
        string $kind,
        string $name,
        string $message,
        array $chars,
        int $index,
    ): array {
        $cp = (int) $ch['cp'];
        return [
            'file' => $file,
            'line' => (int) $ch['line'],
            'column' => (int) $ch['column'],
            'byte' => (int) $ch['byte'],
            'severity' => $severity,
            'kind' => $kind,
            'codepoint' => $ch['invalid'] ? 'byte' : Utf8::format($cp),
            'name' => $name,
            'message' => $message,
            'snippet' => $this->snippet($chars, $index),
        ];
    }

    /**
     * @param list<array<string, mixed>> $chars
     */
    private function snippet(array $chars, int $index): string
    {
        $line = (int) $chars[$index]['line'];
        $parts = [];
        foreach ($chars as $i => $ch) {
            if ($ch['nl'] || (int) $ch['line'] !== $line) {
                continue;
            }
            if ($i === $index) {
                $parts[] = $ch['invalid']
                    ? '[byte 0x' . strtoupper(dechex((int) $ch['cp'])) . ']'
                    : '[' . Utf8::format((int) $ch['cp']) . ']';
                continue;
            }
            if ($ch['invalid']) {
                $parts[] = '?';
                continue;
            }
            $cp = (int) $ch['cp'];
            if ($cp === 0x09) {
                $parts[] = ' ';
                continue;
            }
            if ($cp < 0x20 || $cp === 0x7F) {
                $parts[] = '[' . Utf8::format($cp) . ']';
                continue;
            }
            $parts[] = (string) $ch['ch'];
        }

        $text = implode('', $parts);
        if (strlen($text) <= 180) {
            return $text;
        }

        $pos = strpos($text, $chars[$index]['invalid']
            ? '[byte 0x' . strtoupper(dechex((int) $chars[$index]['cp'])) . ']'
            : '[' . Utf8::format((int) $chars[$index]['cp']) . ']');
        if ($pos === false) {
            return substr($text, 0, 180);
        }
        $from = max(0, $pos - 60);
        $slice = substr($text, $from, 160);
        $prefix = $from > 0 ? '…' : '';
        $suffix = ($from + 160) < strlen($text) ? '…' : '';
        return $prefix . $slice . $suffix;
    }

    /**
     * @param list<array<string, mixed>> $chars
     */
    private function isApostrophe(array $chars, int $index): bool
    {
        $prev = $this->neighbor($chars, $index, -1);
        $next = $this->neighbor($chars, $index, 1);
        if ($prev === null || $next === null) {
            return false;
        }
        return Catalog::isLetterChar($prev) && Catalog::isLetterChar($next);
    }

    /**
     * @param list<array<string, mixed>> $chars
     */
    private function neighbor(array $chars, int $index, int $dir): ?string
    {
        $i = $index + $dir;
        if (!isset($chars[$i]) || $chars[$i]['nl'] || $chars[$i]['invalid']) {
            return null;
        }
        if ((int) $chars[$i]['line'] !== (int) $chars[$index]['line']) {
            return null;
        }
        return (string) $chars[$i]['ch'];
    }

    /**
     * @return array<int, true>
     */
    private function ignoredLines(string $content): array
    {
        $lines = preg_split("/\r\n|\n|\r/", $content);
        if ($lines === false) {
            return [];
        }
        $set = [];
        foreach ($lines as $idx => $line) {
            if (str_contains($line, 'ghostchars:ignore')) {
                $set[$idx + 1] = true;
            }
        }
        return $set;
    }
}

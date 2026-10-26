<?php

declare(strict_types=1);

namespace Ghostchars;

final class Fixer
{
    /**
     * Strips bidi, invisibles (not ZWJ / variation selectors), exotic spaces
     * and curly quotes. Lookalike letters stay: rewriting them would guess.
     *
     * @return array{0:string,1:int}
     */
    public function fix(string $content): array
    {
        $chars = Utf8::decode($content);
        $out = '';
        $edits = 0;
        $count = count($chars);

        for ($i = 0; $i < $count; $i++) {
            $ch = $chars[$i];
            if ($ch['nl']) {
                $out .= $ch['ch'];
                continue;
            }
            if ($ch['invalid']) {
                $edits++;
                continue;
            }

            $apostrophe = false;
            if ($ch['cp'] === 0x2019) {
                $prev = $chars[$i - 1] ?? null;
                $next = $chars[$i + 1] ?? null;
                $apostrophe = $prev !== null && $next !== null
                    && !$prev['nl'] && !$next['nl']
                    && !$prev['invalid'] && !$next['invalid']
                    && (int) $prev['line'] === (int) $ch['line']
                    && (int) $next['line'] === (int) $ch['line']
                    && Catalog::isLetterChar((string) $prev['ch'])
                    && Catalog::isLetterChar((string) $next['ch']);
            }

            $class = Catalog::classify((int) $ch['cp'], (int) $ch['byte'], $apostrophe);
            if ($class === null || $class['strip'] === false) {
                $out .= $ch['ch'];
                continue;
            }

            $edits++;
            if ($class['replace'] !== null) {
                $out .= $class['replace'];
            }
        }

        return [$out, $edits];
    }
}

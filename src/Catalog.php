<?php

declare(strict_types=1);

namespace Ghostchars;

/** The small set of characters that actually show up in pasted code. */
final class Catalog
{
    /** @var array<int, string> */
    private const BIDI_CRITICAL = [
        0x202A => 'LEFT-TO-RIGHT EMBEDDING',
        0x202B => 'RIGHT-TO-LEFT EMBEDDING',
        0x202C => 'POP DIRECTIONAL FORMATTING',
        0x202D => 'LEFT-TO-RIGHT OVERRIDE',
        0x202E => 'RIGHT-TO-LEFT OVERRIDE',
        0x2066 => 'LEFT-TO-RIGHT ISOLATE',
        0x2067 => 'RIGHT-TO-LEFT ISOLATE',
        0x2068 => 'FIRST STRONG ISOLATE',
        0x2069 => 'POP DIRECTIONAL ISOLATE',
    ];

    /** @var array<int, string> */
    private const BIDI_MARK = [
        0x061C => 'ARABIC LETTER MARK',
        0x200E => 'LEFT-TO-RIGHT MARK',
        0x200F => 'RIGHT-TO-LEFT MARK',
    ];

    /**
     * Invisible format characters. U+200D (ZWJ) is intentionally absent:
     * it joins emoji, and stripping it changes the glyph.
     *
     * @var array<int, string>
     */
    private const INVISIBLE = [
        0x00AD => 'SOFT HYPHEN',
        0x034F => 'COMBINING GRAPHEME JOINER',
        0x180E => 'MONGOLIAN VOWEL SEPARATOR',
        0x200B => 'ZERO WIDTH SPACE',
        0x200C => 'ZERO WIDTH NON-JOINER',
        0x2060 => 'WORD JOINER',
        0x2061 => 'FUNCTION APPLICATION',
        0x2062 => 'INVISIBLE TIMES',
        0x2063 => 'INVISIBLE SEPARATOR',
        0x2064 => 'INVISIBLE PLUS',
        0x206A => 'INHIBIT SYMMETRIC SWAPPING',
        0x206B => 'ACTIVATE SYMMETRIC SWAPPING',
        0x206C => 'INHIBIT ARABIC FORM SHAPING',
        0x206D => 'ACTIVATE ARABIC FORM SHAPING',
        0x206E => 'NATIONAL DIGIT SHAPES',
        0x206F => 'NOMINAL DIGIT SHAPES',
        0xFEFF => 'ZERO WIDTH NO-BREAK SPACE',
        0xFFF9 => 'INTERLINEAR ANNOTATION ANCHOR',
        0xFFFA => 'INTERLINEAR ANNOTATION SEPARATOR',
        0xFFFB => 'INTERLINEAR ANNOTATION TERMINATOR',
    ];

    /** @var array<int, string> */
    private const SPACES = [
        0x00A0 => 'NO-BREAK SPACE',
        0x1680 => 'OGHAM SPACE MARK',
        0x2000 => 'EN QUAD',
        0x2001 => 'EM QUAD',
        0x2002 => 'EN SPACE',
        0x2003 => 'EM SPACE',
        0x2004 => 'THREE-PER-EM SPACE',
        0x2005 => 'FOUR-PER-EM SPACE',
        0x2006 => 'SIX-PER-EM SPACE',
        0x2007 => 'FIGURE SPACE',
        0x2008 => 'PUNCTUATION SPACE',
        0x2009 => 'THIN SPACE',
        0x200A => 'HAIR SPACE',
        0x202F => 'NARROW NO-BREAK SPACE',
        0x205F => 'MEDIUM MATHEMATICAL SPACE',
        0x3000 => 'IDEOGRAPHIC SPACE',
    ];

    /** @var array<int, string> curly doubles only. Apostrophes are handled apart. */
    private const DOUBLE_QUOTES = [
        0x201C => 'LEFT DOUBLE QUOTATION MARK',
        0x201D => 'RIGHT DOUBLE QUOTATION MARK',
        0x201E => 'DOUBLE LOW-9 QUOTATION MARK',
        0x201F => 'DOUBLE HIGH-REVERSED-9 QUOTATION MARK',
    ];

    /** @var array<int, string> */
    private const SINGLE_QUOTES = [
        0x2018 => 'LEFT SINGLE QUOTATION MARK',
        0x2019 => 'RIGHT SINGLE QUOTATION MARK',
        0x201A => 'SINGLE LOW-9 QUOTATION MARK',
        0x201B => 'SINGLE HIGH-REVERSED-9 QUOTATION MARK',
    ];

    /**
     * Lookalikes that render as ASCII in a code font.
     * European accents are not here: é is not an attack.
     *
     * @var array<int, array{0:string,1:string}>|null
     */
    private static ?array $confusables = null;

    /** @var array<string, true> */
    private const KEYWORDS = [
        'admin' => true, 'user' => true, 'root' => true, 'password' => true, 'passwd' => true,
        'token' => true, 'secret' => true, 'true' => true, 'false' => true, 'null' => true,
        'eval' => true, 'system' => true, 'exec' => true, 'auth' => true, 'login' => true,
        'role' => true, 'grant' => true, 'allow' => true, 'deny' => true, 'select' => true,
        'insert' => true, 'update' => true, 'delete' => true, 'where' => true, 'from' => true,
        'drop' => true, 'union' => true, 'script' => true, 'function' => true, 'class' => true,
        'public' => true, 'private' => true, 'protected' => true, 'return' => true,
        'require' => true, 'include' => true, 'undefined' => true, 'constructor' => true,
    ];

    /**
     * @return array{severity:string,kind:string,name:string,message:string,strip:bool,replace:?string}|null
     */
    public static function classify(int $cp, int $byte, bool $apostrophe): ?array
    {
        if (isset(self::BIDI_CRITICAL[$cp])) {
            return [
                'severity' => 'critical',
                'kind' => 'bidi',
                'name' => self::BIDI_CRITICAL[$cp],
                'message' => 'Trojan Source (CVE-2021-42574): from here a review and the interpreter can disagree.',
                'strip' => true,
                'replace' => null,
            ];
        }

        if (isset(self::BIDI_MARK[$cp])) {
            return [
                'severity' => 'high',
                'kind' => 'bidi',
                'name' => self::BIDI_MARK[$cp],
                'message' => 'Bidi mark. Invisible, and it reorders the characters around it.',
                'strip' => true,
                'replace' => null,
            ];
        }

        if ($cp === 0xFEFF) {
            $atStart = $byte === 0;
            return [
                'severity' => $atStart ? 'medium' : 'critical',
                'kind' => 'invisible',
                'name' => 'ZERO WIDTH NO-BREAK SPACE',
                'message' => $atStart
                    ? 'UTF-8 BOM at the start of the file. PHP will send those bytes before any header.'
                    : 'BOM in the middle of the file. Invisible, and it breaks equality checks.',
                'strip' => true,
                'replace' => null,
            ];
        }

        if (isset(self::INVISIBLE[$cp]) || self::isTag($cp)) {
            return [
                'severity' => 'high',
                'kind' => 'invisible',
                'name' => self::INVISIBLE[$cp] ?? 'TAG CHARACTER',
                'message' => 'Invisible character. strlen counts it. A review does not.',
                'strip' => true,
                'replace' => null,
            ];
        }

        if ($cp === 0x200D || self::isVariation($cp)) {
            return [
                'severity' => 'medium',
                'kind' => 'invisible',
                'name' => $cp === 0x200D ? 'ZERO WIDTH JOINER' : 'VARIATION SELECTOR',
                'message' => 'Format character. Kept by fix, because emoji use it. Still invisible in a diff.',
                'strip' => false,
                'replace' => null,
            ];
        }

        if ($cp < 0x20 || ($cp >= 0x7F && $cp <= 0x9F)) {
            if ($cp === 0x09) {
                return null;
            }
            return [
                'severity' => $cp === 0x00 ? 'critical' : 'high',
                'kind' => 'control',
                'name' => $cp === 0x00 ? 'NULL' : 'CONTROL CHARACTER',
                'message' => 'Control character. It does not belong in source.',
                'strip' => true,
                'replace' => null,
            ];
        }

        if (isset(self::SPACES[$cp])) {
            return [
                'severity' => 'medium',
                'kind' => 'space',
                'name' => self::SPACES[$cp],
                'message' => 'Exotic space. It looks like a space and fails a URL, a YAML key, or a parser.',
                'strip' => true,
                'replace' => ' ',
            ];
        }

        if (isset(self::DOUBLE_QUOTES[$cp])) {
            return [
                'severity' => 'medium',
                'kind' => 'quote',
                'name' => self::DOUBLE_QUOTES[$cp],
                'message' => 'Curly double quote, usually pasted from Slack or Docs. It is not a PHP or JSON quote.',
                'strip' => true,
                'replace' => '"',
            ];
        }

        if (isset(self::SINGLE_QUOTES[$cp])) {
            if ($cp === 0x2019 && $apostrophe) {
                return null;
            }
            return [
                'severity' => 'medium',
                'kind' => 'quote',
                'name' => self::SINGLE_QUOTES[$cp],
                'message' => 'Curly single quote used as a delimiter, not as a French apostrophe.',
                'strip' => true,
                'replace' => "'",
            ];
        }

        return null;
    }

    /**
     * @return array{0:string,1:string}|null ascii lookalike, unicode name
     */
    public static function confusable(int $cp): ?array
    {
        $map = self::confusables();
        return $map[$cp] ?? null;
    }

    public static function isKeyword(string $skeleton): bool
    {
        $word = strtolower(ltrim($skeleton, '$'));
        return isset(self::KEYWORDS[$word]);
    }

    public static function isIdentByte(int $cp): bool
    {
        if ($cp === 0x24 || $cp === 0x5F) {
            return true;
        }
        if (($cp >= 0x30 && $cp <= 0x39) || ($cp >= 0x41 && $cp <= 0x5A) || ($cp >= 0x61 && $cp <= 0x7A)) {
            return true;
        }
        return self::confusable($cp) !== null;
    }

    public static function isAsciiLetter(int $cp): bool
    {
        return ($cp >= 0x41 && $cp <= 0x5A) || ($cp >= 0x61 && $cp <= 0x7A) || ($cp >= 0x30 && $cp <= 0x39);
    }

    public static function isLetterChar(string $ch): bool
    {
        return preg_match('/^\p{L}$/u', $ch) === 1;
    }

    private static function isTag(int $cp): bool
    {
        return $cp === 0xE0001 || ($cp >= 0xE0020 && $cp <= 0xE007F);
    }

    private static function isVariation(int $cp): bool
    {
        return ($cp >= 0xFE00 && $cp <= 0xFE0F) || ($cp >= 0xE0100 && $cp <= 0xE01EF);
    }

    /**
     * @return array<int, array{0:string,1:string}>
     */
    private static function confusables(): array
    {
        if (self::$confusables !== null) {
            return self::$confusables;
        }

        $map = [
            0x0430 => ['a', 'CYRILLIC SMALL LETTER A'],
            0x0435 => ['e', 'CYRILLIC SMALL LETTER IE'],
            0x043A => ['k', 'CYRILLIC SMALL LETTER KA'],
            0x043C => ['m', 'CYRILLIC SMALL LETTER EM'],
            0x043D => ['H', 'CYRILLIC SMALL LETTER EN'],
            0x043E => ['o', 'CYRILLIC SMALL LETTER O'],
            0x0440 => ['p', 'CYRILLIC SMALL LETTER ER'],
            0x0441 => ['c', 'CYRILLIC SMALL LETTER ES'],
            0x0443 => ['y', 'CYRILLIC SMALL LETTER U'],
            0x0445 => ['x', 'CYRILLIC SMALL LETTER HA'],
            0x0455 => ['s', 'CYRILLIC SMALL LETTER DZE'],
            0x0456 => ['i', 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I'],
            0x0458 => ['j', 'CYRILLIC SMALL LETTER JE'],
            0x04CF => ['l', 'CYRILLIC SMALL LETTER PALOCHKA'],
            0x0406 => ['I', 'CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I'],
            0x0410 => ['A', 'CYRILLIC CAPITAL LETTER A'],
            0x0412 => ['B', 'CYRILLIC CAPITAL LETTER VE'],
            0x0415 => ['E', 'CYRILLIC CAPITAL LETTER IE'],
            0x041A => ['K', 'CYRILLIC CAPITAL LETTER KA'],
            0x041C => ['M', 'CYRILLIC CAPITAL LETTER EM'],
            0x041D => ['H', 'CYRILLIC CAPITAL LETTER EN'],
            0x041E => ['O', 'CYRILLIC CAPITAL LETTER O'],
            0x0420 => ['P', 'CYRILLIC CAPITAL LETTER ER'],
            0x0421 => ['C', 'CYRILLIC CAPITAL LETTER ES'],
            0x0422 => ['T', 'CYRILLIC CAPITAL LETTER TE'],
            0x0425 => ['X', 'CYRILLIC CAPITAL LETTER HA'],
            0x04C0 => ['I', 'CYRILLIC LETTER PALOCHKA'],
            0x0391 => ['A', 'GREEK CAPITAL LETTER ALPHA'],
            0x0392 => ['B', 'GREEK CAPITAL LETTER BETA'],
            0x0395 => ['E', 'GREEK CAPITAL LETTER EPSILON'],
            0x0396 => ['Z', 'GREEK CAPITAL LETTER ZETA'],
            0x0397 => ['H', 'GREEK CAPITAL LETTER ETA'],
            0x0399 => ['I', 'GREEK CAPITAL LETTER IOTA'],
            0x039A => ['K', 'GREEK CAPITAL LETTER KAPPA'],
            0x039C => ['M', 'GREEK CAPITAL LETTER MU'],
            0x039D => ['N', 'GREEK CAPITAL LETTER NU'],
            0x039F => ['O', 'GREEK CAPITAL LETTER OMICRON'],
            0x03A1 => ['P', 'GREEK CAPITAL LETTER RHO'],
            0x03A4 => ['T', 'GREEK CAPITAL LETTER TAU'],
            0x03A5 => ['Y', 'GREEK CAPITAL LETTER UPSILON'],
            0x03A7 => ['X', 'GREEK CAPITAL LETTER CHI'],
            0x03BF => ['o', 'GREEK SMALL LETTER OMICRON'],
            0x03C1 => ['p', 'GREEK SMALL LETTER RHO'],
        ];

        for ($i = 0; $i < 26; $i++) {
            $map[0xFF21 + $i] = [chr(ord('A') + $i), 'FULLWIDTH LATIN CAPITAL LETTER ' . chr(ord('A') + $i)];
            $map[0xFF41 + $i] = [chr(ord('a') + $i), 'FULLWIDTH LATIN SMALL LETTER ' . chr(ord('a') + $i)];
        }
        for ($i = 0; $i < 10; $i++) {
            $map[0xFF10 + $i] = [chr(ord('0') + $i), 'FULLWIDTH DIGIT ' . chr(ord('0') + $i)];
        }

        self::$confusables = $map;
        return $map;
    }
}

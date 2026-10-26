<?php

declare(strict_types=1);

namespace Ghostchars;

/** Byte-accurate UTF-8 walk. Invalid bytes stay visible instead of being swallowed. */
final class Utf8
{
    /**
     * @return list<array{
     *   cp:int, ch:string, byte:int, len:int, line:int, column:int,
     *   invalid:bool, nl:bool
     * }>
     */
    public static function decode(string $content): array
    {
        $out = [];
        $n = strlen($content);
        $i = 0;
        $line = 1;
        $col = 1;

        while ($i < $n) {
            $b0 = ord($content[$i]);

            if ($b0 === 0x0D) {
                $len = ($i + 1 < $n && ord($content[$i + 1]) === 0x0A) ? 2 : 1;
                $out[] = self::item(0x0A, substr($content, $i, $len), $i, $len, $line, $col, false, true);
                $i += $len;
                $line++;
                $col = 1;
                continue;
            }

            if ($b0 === 0x0A) {
                $out[] = self::item(0x0A, "\n", $i, 1, $line, $col, false, true);
                $i++;
                $line++;
                $col = 1;
                continue;
            }

            [$cp, $len, $invalid] = self::sequence($content, $i, $n);
            $ch = substr($content, $i, $invalid ? 1 : $len);
            $out[] = self::item($cp, $ch, $i, $invalid ? 1 : $len, $line, $col, $invalid, false);
            $i += $invalid ? 1 : $len;
            $col++;
        }

        return $out;
    }

    public static function format(int $cp): string
    {
        return sprintf('U+%04X', $cp);
    }

    /**
     * @return array{0:int,1:int,2:bool} cp, length, invalid
     */
    private static function sequence(string $s, int $i, int $n): array
    {
        $b0 = ord($s[$i]);
        $need = match (true) {
            $b0 <= 0x7F => 1,
            $b0 >= 0xC2 && $b0 <= 0xDF => 2,
            $b0 >= 0xE0 && $b0 <= 0xEF => 3,
            $b0 >= 0xF0 && $b0 <= 0xF4 => 4,
            default => 0,
        };

        if ($need === 0 || $i + $need > $n) {
            return [$b0, 1, true];
        }

        $bytes = [];
        for ($k = 0; $k < $need; $k++) {
            $bytes[] = ord($s[$i + $k]);
        }
        for ($k = 1; $k < $need; $k++) {
            if (($bytes[$k] & 0xC0) !== 0x80) {
                return [$b0, 1, true];
            }
        }

        if ($need === 3) {
            $b1 = $bytes[1];
            if ($b0 === 0xE0 && $b1 < 0xA0) {
                return [$b0, 1, true];
            }
            if ($b0 === 0xED && $b1 >= 0xA0) {
                return [$b0, 1, true];
            }
        }
        if ($need === 4) {
            $b1 = $bytes[1];
            if ($b0 === 0xF0 && $b1 < 0x90) {
                return [$b0, 1, true];
            }
            if ($b0 === 0xF4 && $b1 >= 0x90) {
                return [$b0, 1, true];
            }
        }

        $cp = match ($need) {
            1 => $bytes[0],
            2 => (($bytes[0] & 0x1F) << 6) | ($bytes[1] & 0x3F),
            3 => (($bytes[0] & 0x0F) << 12) | (($bytes[1] & 0x3F) << 6) | ($bytes[2] & 0x3F),
            default => (($bytes[0] & 0x07) << 18)
                | (($bytes[1] & 0x3F) << 12)
                | (($bytes[2] & 0x3F) << 6)
                | ($bytes[3] & 0x3F),
        };

        return [$cp, $need, false];
    }

    /**
     * @return array{cp:int,ch:string,byte:int,len:int,line:int,column:int,invalid:bool,nl:bool}
     */
    private static function item(
        int $cp,
        string $ch,
        int $byte,
        int $len,
        int $line,
        int $column,
        bool $invalid,
        bool $nl,
    ): array {
        return [
            'cp' => $cp,
            'ch' => $ch,
            'byte' => $byte,
            'len' => $len,
            'line' => $line,
            'column' => $column,
            'invalid' => $invalid,
            'nl' => $nl,
        ];
    }
}

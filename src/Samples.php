<?php

declare(strict_types=1);

namespace Ghostchars;

/** Built with \u escapes so this file itself stays scannable. */
final class Samples
{
    public static function dirty(): string
    {
        return "<?php\n"
            . "\n"
            . "declare(strict_types=1);\n"
            . "\n"
            . "// Copied from a doc. Looks reviewed. It is not.\n"
            . "\n"
            . "function save\u{200B}User(): void\n"
            . "{\n"
            . "    return;\n"
            . "}\n"
            . "\n"
            . "\$role = \"user\u{202E}admin\";\n"
            . "\n"
            . "\$\u{0430}dmin = true;\n"
            . "if (\$\u{0430}dmin) {\n"
            . "    echo \"granted\\n\";\n"
            . "}\n"
            . "\n"
            . "\$url = \"https://example.com/a\u{00A0}b\";\n"
            . "// pasted from Slack: \u{201C}ok\u{201D}\n";
    }

    public static function clean(): string
    {
        return "<?php\n"
            . "\n"
            . "declare(strict_types=1);\n"
            . "\n"
            . "function saveUser(): void\n"
            . "{\n"
            . "    return;\n"
            . "}\n"
            . "\n"
            . "\$role = \"useradmin\";\n"
            . "\$admin = true;\n"
            . "if (\$admin) {\n"
            . "    echo \"granted\\n\";\n"
            . "}\n"
            . "\n"
            . "\$url = \"https://example.com/ab\";\n"
            . "\$label = \"ok\";\n"
            . "echo \"l\u{2019}équipe a déjà payé\\n\";\n"
            . "\$dew = \"\u{0440}\u{043E}\u{0441}\u{0430}\";\n";
    }
}

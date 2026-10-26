<?php

declare(strict_types=1);

require __DIR__ . '/../ghostchars.php';

use Ghostchars\Cli;
use Ghostchars\Fixer;
use Ghostchars\Samples;
use Ghostchars\Scanner;

$fail = 0;
$ok = 0;

function check(bool $cond, string $msg): void
{
    global $fail, $ok;
    if ($cond) {
        $ok++;
        echo "ok   {$msg}\n";
        return;
    }
    $fail++;
    echo "FAIL {$msg}\n";
}

function kind(array $findings, string $kind): array
{
    return array_values(array_filter($findings, static fn (array $f): bool => $f['kind'] === $kind));
}

function severity(array $findings, string $severity): array
{
    return array_values(array_filter($findings, static fn (array $f): bool => $f['severity'] === $severity));
}

$scanner = new Scanner();
$fixer = new Fixer();
$root = dirname(__DIR__);
$php = PHP_BINARY;

function runCli(string $php, string $root, array $args, string $stdin = ''): array
{
    $cmd = escapeshellarg($php) . ' ' . escapeshellarg($root . '/ghostchars.php');
    foreach ($args as $arg) {
        $cmd .= ' ' . escapeshellarg($arg);
    }
    $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root);
    if (!is_resource($proc)) {
        return [127, '', 'proc_open failed'];
    }
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return [$code, is_string($out) ? $out : '', is_string($err) ? $err : ''];
}

$dirty = Samples::dirty();
$clean = Samples::clean();
$found = $scanner->scan($dirty, 'dirty.php');

check($scanner->scan($clean, 'clean.php') === [], 'french, accents and a cyrillic word that is not a spoof stay quiet');
check($scanner->scan("<?php\n\$price = 10;\n", 'a.php') === [], 'plain ascii is clean');

$invis = kind($found, 'invisible');
check(count($invis) === 1 && $invis[0]['codepoint'] === 'U+200B' && $invis[0]['column'] === 14, 'zero-width space is column 14 of the function name');
check($invis[0]['severity'] === 'high' && $invis[0]['line'] === 7, 'zero-width space is high on line 7');

$bidi = kind($found, 'bidi');
check(count($bidi) === 1 && $bidi[0]['severity'] === 'critical' && $bidi[0]['codepoint'] === 'U+202E', 'right-to-left override is critical');
check(str_contains($bidi[0]['message'], 'CVE-2021-42574'), 'bidi finding names Trojan Source');

$homo = kind($found, 'homoglyph');
check(count($homo) === 2 && $homo[0]['codepoint'] === 'U+0430' && $homo[0]['column'] === 2, 'cyrillic a in $admin is column 2');
check(str_contains($homo[0]['message'], '"$admin"'), 'skeleton of the variable is $admin');
check($homo[1]['line'] === 15 && $homo[1]['column'] === 6, 'second lookalike is the if condition');

$spaces = kind($found, 'space');
check(count($spaces) === 1 && $spaces[0]['codepoint'] === 'U+00A0' && $spaces[0]['severity'] === 'medium', 'nbsp inside the url is medium');

$quotes = kind($found, 'quote');
check(count($quotes) === 2 && $quotes[0]['codepoint'] === 'U+201C' && $quotes[1]['codepoint'] === 'U+201D', 'curly double quotes in the comment are found');

check(count(severity($found, 'critical')) === 1, 'one critical');
check(count(severity($found, 'high')) === 3, 'zwsp plus two homoglyphs');
check(count(severity($found, 'medium')) === 3, 'nbsp plus two quotes');

$ignored = $scanner->scan("<?php\n\$\u{0430}dmin = true; // ghostchars:ignore\n", 'i.php');
check($ignored === [], 'ghostchars:ignore skips the line');

$apo = $scanner->scan("<?php\necho \"l\u{2019}équipe\";\n", 'fr.php');
check($apo === [], 'a French apostrophe between letters is not a quote bug');

$lone = $scanner->scan("<?php\n\$label = \u{2018}ok\u{2019};\n", 'q.php');
check(count(kind($lone, 'quote')) === 2, 'curly singles used as delimiters are quotes');

$russian = $scanner->scan("<?php\n\$dew = \"\u{0440}\u{043E}\u{0441}\u{0430}\";\n", 'ru.php');
check($russian === [], 'a real cyrillic word is not a mixed-script spoof');

$var = $scanner->scan("<?php\n\$\u{0430} = 1;\n", 'v.php');
check(count($var) === 1 && $var[0]['kind'] === 'homoglyph', 'a one-letter lookalike variable is still a spoof');

$full = $scanner->scan("<?php\n\$ok = \u{FF54}\u{FF52}\u{FF55}\u{FF45};\n", 'fw.php');
check(count($full) === 4 && $full[0]['message'] !== '' && str_contains($full[0]['message'], 'true'), 'fullwidth true is a lookalike keyword');

$greek = $scanner->scan("<?php\n\$name = \"\u{039F}K\";\n", 'gk.php');
check(count($greek) === 1 && $greek[0]['codepoint'] === 'U+039F', 'greek omicron mixed with ASCII is a spoof');
check($scanner->scan("<?php\n\$name = \"Ωμέγα\";\n", 'gk2.php') === [], 'a greek word is not flagged');

$bom = $scanner->scan("\u{FEFF}<?php\n", 'bom.php');
check(count($bom) === 1 && $bom[0]['severity'] === 'medium' && $bom[0]['column'] === 1, 'a leading BOM is medium');
$mid = $scanner->scan("<?php\n\$a = 1;\u{FEFF}\n", 'mid.php');
check(count($mid) === 1 && $mid[0]['severity'] === 'critical', 'a BOM in the middle is critical');

$nul = $scanner->scan("<?php\n\$a = \"a\0b\";\n", 'nul.php');
check(count(kind($nul, 'control')) === 1 && $nul[0]['severity'] === 'critical', 'NUL is critical');

$bad = $scanner->scan("<?php\n\$a = \"\xFF\";\n", 'bad.php');
check(count(kind($bad, 'utf8')) === 1 && $bad[0]['severity'] === 'critical', 'invalid utf-8 is critical');

$zwj = "<?php\n\$emoji = \"a\u{200D}b\";\n";
$zwjFound = $scanner->scan($zwj, 'emoji.php');
check(count($zwjFound) === 1 && $zwjFound[0]['severity'] === 'medium' && $zwjFound[0]['codepoint'] === 'U+200D', 'zwj is reported and not high');
[$zwjFixed, $zwjEdits] = $fixer->fix($zwj);
check($zwjEdits === 0 && str_contains($zwjFixed, "\u{200D}"), 'fix keeps the emoji joiner');

[$fixed, $edits] = $fixer->fix($dirty);
check($edits === 5, 'fix edits zwsp, rlo, nbsp and two quotes');
$left = $scanner->scan($fixed, 'fixed.php');
check(kind($left, 'invisible') === [] && kind($left, 'bidi') === [] && kind($left, 'space') === [] && kind($left, 'quote') === [], 'fix clears invisibles, bidi, spaces and quotes');
check(count(kind($left, 'homoglyph')) === 2, 'fix does not rewrite the cyrillic a');
check(str_contains($fixed, 'function saveUser(): void'), 'function name is whole again');
check(str_contains($fixed, '$role = "useradmin";'), 'rlo is gone from the string');
check(str_contains($fixed, 'https://example.com/a b'), 'nbsp became a normal space');

$crlf = "<?php\r\n\$a = \"a\u{200B}b\";\r\n";
[$crlfFixed, ] = $fixer->fix($crlf);
check(str_contains($crlfFixed, "\r\n") && !str_contains($crlfFixed, "\u{200B}"), 'crlf stays, zwsp goes');

$apoFixed = $fixer->fix("l\u{2019}équipe")[0];
check($apoFixed === "l\u{2019}équipe", 'fix keeps a French apostrophe');

check(Cli::fails($found, 'high') === true, 'default gate fails on high');
check(Cli::fails(kind($found, 'space'), 'high') === false, 'medium alone does not fail the default gate');
check(Cli::fails($found, 'none') === false, 'fail-on none never fails');
check(Cli::fails(kind($found, 'quote'), 'medium') === true, 'fail-on medium catches quotes');

$examples = $root . '/examples';
@mkdir($examples . '/dirty', 0777, true);
@mkdir($examples . '/clean', 0777, true);
file_put_contents($examples . '/dirty/Auth.php', $dirty);
file_put_contents($examples . '/clean/Auth.php', $clean);
check(file_get_contents($examples . '/dirty/Auth.php') === $dirty, 'dirty fixture matches the sample');

[$code, $out, $err] = runCli($php, $root, ['demo']);
check($code === 0 && str_contains($out, 'NOT equal') && str_contains($out, 'U+202E') && str_contains($out, 'critical'), 'demo prints the live comparison and the scan');
check($err === '', 'demo stays quiet on stderr');

[$code, $out] = runCli($php, $root, ['scan', 'examples/clean']);
check($code === 0 && str_contains($out, '0 findings'), 'scan clean exits 0');

[$code, $out] = runCli($php, $root, ['scan', 'examples/dirty']);
check($code === 1 && str_contains($out, 'U+202E') && str_contains($out, 'U+0430'), 'scan dirty exits 1');

[$code, $out] = runCli($php, $root, ['scan', '--json', '--fail-on=none', 'examples/dirty']);
$json = json_decode($out, true);
check($code === 0 && is_array($json) && $json['failed'] === false && $json['counts']['critical'] === 1, 'json and fail-on none');

[$code, $out, $err] = runCli($php, $root, ['scan', 'missing.php']);
check($code === 2 && str_contains($err, 'not found'), 'missing file is exit 2');

[$code, $out] = runCli($php, $root, ['scan', '-'], "<?php\n\$\u{0430}dmin = 1;\n");
check($code === 1 && str_contains($out, 'stdin:'), 'stdin scan names the file stdin');

$tmp = sys_get_temp_dir() . '/ghostchars-' . getmypid();
@mkdir($tmp . '/vendor', 0777, true);
@mkdir($tmp . '/src', 0777, true);
file_put_contents($tmp . '/vendor/Bad.php', "<?php\n\$\u{0430}dmin = 1;\n");
file_put_contents($tmp . '/src/Ok.php', "<?php\n\$admin = 1;\n");
file_put_contents($tmp . '/src/Bin.php', "<?php\0hidden");
[$code, $out] = runCli($php, $root, ['scan', $tmp]);
check($code === 0 && str_contains($out, '0 findings'), 'vendor and binary files are skipped');

$copy = $tmp . '/src/Dirty.php';
file_put_contents($copy, $dirty);
[$code, $out] = runCli($php, $root, ['fix', '--write', $copy]);
check($code === 0 && str_contains($out, 'fixed'), 'fix --write reports the file');
$rewritten = file_get_contents($copy);
check(is_string($rewritten) && !str_contains($rewritten, "\u{200B}") && str_contains($rewritten, "\u{0430}"), 'written file dropped the invisible and kept the lookalike');

$lint = proc_open(
    escapeshellarg($php) . ' -l ' . escapeshellarg($copy),
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $lintPipes,
);
$lintOut = stream_get_contents($lintPipes[1]);
$lintCode = proc_close($lint);
check($lintCode === 0 && is_string($lintOut) && str_contains($lintOut, 'No syntax errors'), 'fixed dirty file still parses');

[$code, $out] = runCli($php, $root, ['fix'], "<?php\nfunction save\u{200B}User() {}\n");
check($code === 0 && str_contains($out, 'function saveUser()'), 'fix from stdin prints the cleaned source');

[$code] = runCli($php, $root, ['scan', 'src', 'tests', 'ghostchars.php']);
check($code === 0, 'the project source has nothing to report');

[$code] = runCli($php, $root, ['nope']);
check($code === 2, 'unknown command is exit 2');

echo "\n{$ok} passed, {$fail} failed\n";
exit($fail === 0 ? 0 : 1);

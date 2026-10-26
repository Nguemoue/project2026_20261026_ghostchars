# ghostchars

**Le caractère que le diff ne montre pas.** CLI PHP, zéro dépendance.

Un `a` cyrillique, un espace de largeur nulle collé depuis Slack, un override droite-à-gauche. La review lit une chose. PHP en exécute une autre.

```bash
php ghostchars.php demo
php ghostchars.php scan src/
php ghostchars.php fix path/to/File.php --write
```

Rien n'est envoyé nulle part. Le scan lit des fichiers locaux. Pas de télémétrie.

## Le problème

Trois caractères passent un `git diff` sans se faire voir.

1. **Sosie.** `U+0430` (CYRILLIC SMALL LETTER A) a le même dessin que `a`. `$admin === $аdmin` est faux. Le premier caractère de droite n'est pas latin.
2. **Invisible.** `U+200B` ZERO WIDTH SPACE compte dans `strlen` et dans un nom de fonction. L'œil en voit 8, PHP en lit 9.
3. **Trojan Source.** `U+202E` RIGHT-TO-LEFT OVERRIDE (CVE-2021-42574) peut faire lire une ligne à l'envers à la review, pendant que l'interpréteur suit l'ordre logique.

Ça arrive en collant depuis Slack, Notion, Google Docs, Word, ou une réponse de chat. Le test reste vert. L'égalité, non.

La sortie ci-dessous est celle du binaire, pas un exemple inventé.

```text
$ php ghostchars.php demo
ghostchars  the character the diff does not show

admin === аdmin
  left    U+0061 LATIN SMALL LETTER A
  right   U+0430 CYRILLIC SMALL LETTER A
  php     NOT equal
  a review reads both as admin

function name save + zero-width space + User
  bytes    11
  chars    9
  you see  8

U+202E inside a string is valid PHP. A reviewer can read the other order.
Trojan Source, CVE-2021-42574.

<demo>:7:14  high  invisible  U+200B  ZERO WIDTH SPACE
  Invisible character. strlen counts it. A review does not.
  function save[U+200B]User(): void

<demo>:12:14  critical  bidi  U+202E  RIGHT-TO-LEFT OVERRIDE
  Trojan Source (CVE-2021-42574): from here a review and the interpreter can disagree.
  $role = "user[U+202E]admin";

<demo>:14:2  high  homoglyph  U+0430  CYRILLIC SMALL LETTER A
  Looks like "a" (U+0061). Token skeletons to "$admin".
  $[U+0430]dmin = true;

<demo>:15:6  high  homoglyph  U+0430  CYRILLIC SMALL LETTER A
  Looks like "a" (U+0061). Token skeletons to "$admin".
  if ($[U+0430]dmin) {

<demo>:19:30  medium  space  U+00A0  NO-BREAK SPACE
  Exotic space. It looks like a space and fails a URL, a YAML key, or a parser.
  $url = "https://example.com/a[U+00A0]b";

<demo>:20:23  medium  quote  U+201C  LEFT DOUBLE QUOTATION MARK
  Curly double quote, usually pasted from Slack or Docs. It is not a PHP or JSON quote.
  // pasted from Slack: [U+201C]ok”

<demo>:20:26  medium  quote  U+201D  RIGHT DOUBLE QUOTATION MARK
  Curly double quote, usually pasted from Slack or Docs. It is not a PHP or JSON quote.
  // pasted from Slack: “ok[U+201D]

ghostchars  7 findings  critical 1  high 3  medium 3

fix strips bidi, invisibles, exotic spaces and curly quotes.
It does not rewrite the cyrillic a. That is a different letter.
Nothing is uploaded.
```

`examples/dirty/Auth.php` est du PHP valide (`php -l` passe) et il est sale. `examples/clean/Auth.php` contient des accents, une apostrophe française `l’équipe` et le mot cyrillique « роса ». Le scan y est vide : ce ne sont pas des sosies collés à de l'ASCII.

```text
$ php ghostchars.php scan examples/dirty
examples/dirty/Auth.php:7:14  high  invisible  U+200B  ZERO WIDTH SPACE
  Invisible character. strlen counts it. A review does not.
  function save[U+200B]User(): void

examples/dirty/Auth.php:12:14  critical  bidi  U+202E  RIGHT-TO-LEFT OVERRIDE
  Trojan Source (CVE-2021-42574): from here a review and the interpreter can disagree.
  $role = "user[U+202E]admin";

examples/dirty/Auth.php:14:2  high  homoglyph  U+0430  CYRILLIC SMALL LETTER A
  Looks like "a" (U+0061). Token skeletons to "$admin".
  $[U+0430]dmin = true;

examples/dirty/Auth.php:15:6  high  homoglyph  U+0430  CYRILLIC SMALL LETTER A
  Looks like "a" (U+0061). Token skeletons to "$admin".
  if ($[U+0430]dmin) {

examples/dirty/Auth.php:19:30  medium  space  U+00A0  NO-BREAK SPACE
  Exotic space. It looks like a space and fails a URL, a YAML key, or a parser.
  $url = "https://example.com/a[U+00A0]b";

examples/dirty/Auth.php:20:23  medium  quote  U+201C  LEFT DOUBLE QUOTATION MARK
  Curly double quote, usually pasted from Slack or Docs. It is not a PHP or JSON quote.
  // pasted from Slack: [U+201C]ok”

examples/dirty/Auth.php:20:26  medium  quote  U+201D  RIGHT DOUBLE QUOTATION MARK
  Curly double quote, usually pasted from Slack or Docs. It is not a PHP or JSON quote.
  // pasted from Slack: “ok[U+201D]

ghostchars  7 findings  critical 1  high 3  medium 3
```

Exit `1` dès qu'il y a un `critical` ou un `high`. Un `medium` seul ne casse pas la CI.

## Réparer

`fix` retire les marques bidi, les invisibles, les espaces exotiques et les guillemets courbes. Il les remplace par leur équivalent ASCII quand il y en a un (espace, `"`).

Il **ne réécrit pas** une lettre sosie. `а` et `a` sont deux lettres, et l'outil ne devine pas laquelle tu voulais.

Le joiner d'emoji (`U+200D`) est signalé en `medium` et laissé en place : le retirer change le glyphe.

```bash
php ghostchars.php fix examples/dirty/Auth.php          # imprime le fichier nettoyé
php ghostchars.php fix examples/dirty/Auth.php --write  # réécrit sur place
php ghostchars.php fix < collage.php > propre.php
```

Une ligne qui contient `ghostchars:ignore` est sautée.

## Ce qui est signalé

| sévérité | kind | exemples |
| --- | --- | --- |
| critical | bidi | U+202A–U+202E, U+2066–U+2069, un BOM au milieu du fichier |
| critical | control, utf8 | NUL, UTF-8 invalide |
| high | invisible | U+200B, U+200C, U+00AD, U+FEFF hors début, tags Unicode |
| high | homoglyph | cyrillique, grec ou pleine chasse **mélangé** à de l'ASCII, ou un jeton entier qui est un mot-clé (`admin`, `true`, `password`, …) |
| high | bidi | marques LRM, RLM, Arabic letter mark |
| medium | space | NBSP, fine insécable, espace idéographique |
| medium | quote | guillemets “ ” copiés depuis Slack. L'apostrophe `’` entre deux lettres est laissée (français) |
| medium | invisible | BOM en tête de fichier, ZWJ, sélecteurs de variation |

`--fail-on=medium` fait échouer aussi les medium. `--fail-on=none` affiche et sort 0. Défaut : `high`.

```bash
php ghostchars.php scan src/ --json
php ghostchars.php scan src/ --fail-on=medium
php ghostchars.php scan -   # stdin
```

Ce n'est pas tout Unicode. Le catalogue des sosies couvre les lettres qui se confondent vraiment dans une police de code (cyrillique, capitales grecques, pleine chasse), pas `é` ni `à`. Un mot entièrement cyrillique n'est pas un mélange : il n'est signalé que s'il est un sosie d'un mot-clé, ou un nom de variable PHP (`$`).

Les répertoires `vendor/`, `node_modules/`, `.git/` sont ignorés. Un fichier binaire (octet NUL) ou de plus de 2 Mo aussi. Extensions lues dans un dossier : php, js, ts, vue, json, yaml, xml, twig, sql, html, css, et `.env`. Un fichier passé explicitement est lu quelle que soit son extension.

## CI

```yaml
- run: php ghostchars.php scan src/
```

Les tests du dépôt tournent sur PHP 8.2, 8.3 et 8.4.

```bash
php tests/run.php
```

PHP `>= 8.1`. Aucune extension requise.

## Licence

MIT.

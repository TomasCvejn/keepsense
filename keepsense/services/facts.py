"""Deterministic meaning check: which facts did a rewrite lose or change?

Design principle: a false alarm is cheap, a missed change is expensive.

Sources the rules come from:
- translate-toolkit pofilter, Okapi CheckMate, Weblate: source/target QA checks
  (numbers, URLs, placeholders), compared as multisets, never as substrings
- GitHub autolink and Asciidoctor rules for where a URL ends
- NegEx / negspaCy trigger lists for negation cues and pseudo-negations
- RFC 2119 / RFC 8174 and the Google and Red Hat style guides for requirement levels
- MSRP and ASSET paraphrase corpora for how much shorter a paraphrase gets
"""

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

Kind = Literal["number", "negation", "code", "url", "modality", "scope", "length"]
Severity = Literal["error", "warning"]


@dataclass
class Issue:
    kind: Kind
    severity: Severity
    message: str
    missing: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)


# Replaces every extracted fact, so later checks don't see it a second time.
MASK = "\x00"
# Marks a number that was written as a word ("two"), see Facts.numbers().
SPELLED = "\x01"

# Characters LLMs swap without changing meaning. Not NFKC: it turns 2⁹ into 29.
# En/em dashes stay: "—force" instead of "--force" is a broken flag.
CHARACTERS = str.maketrans(
    {
        "‘": "'", "’": "'", "ʼ": "'", "′": "'", "＇": "'",
        "“": '"', "”": '"',
        "−": "-",
        " ": " ", " ": " ", " ": " ",
    }
)  # fmt: skip

# --- formatted code ------------------------------------------------------------

# ```lang / ~~~ fences (Markdown), ---- listing blocks (AsciiDoc).
# ponytail: a Markdown "----" rule pair reads as a code block,
# detect AsciiDoc if it bites
BLOCK = re.compile(
    r"^[ \t]*(```|~~~|-{4,}+)[^\n]*+\n(.*?)^[ \t]*\1[ \t]*$", re.M | re.S
)
INLINE_CODE = re.compile(r"`([^`\n]+)`")
# AsciiDoc passthrough: `+oc get pods+` is the same code as `oc get pods`
PASSTHROUGH = re.compile(r"^\+(.+)\+$")

# 1. / 1) / - / * / ** (Markdown, AsciiDoc) and . (AsciiDoc ordered list)
LIST_ITEM = re.compile(r"^[ \t]*(?:\d+[.)]|[-*+]+|\.+)[ \t]+(?=\S)(.*)$", re.M)

# --- links ---------------------------------------------------------------------

# [ ] end the URL: AsciiDoc https://example.com[link text], Markdown [text](url)
URL = re.compile(r"""(?:https?://|www\.)[^\s<>"'`\[\]]+""", re.I)
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# Trailing characters that end a sentence rather than a URL (GitHub autolink rules).
TRAILING = ".,;:!?*_~'\""

# --- code-like tokens in prose -------------------------------------------------

FILE_EXT = (
    "yaml|yml|json|toml|ini|conf|cfg|env|properties|xml|txt|log|md|adoc|"
    "sh|bash|py|go|js|ts|rb|pl|j2|tf|repo|service|socket|timer|"
    "crt|pem|key|csr|cer|p12|tar|gz|tgz|zip|rpm|iso|img|qcow2"
)
# Product names are PascalCase too, but they are not API kinds.
PRODUCT_NAMES = (
    "OpenShift|GitHub|GitLab|JavaScript|TypeScript|PowerShell|PostgreSQL|MySQL|"
    "MariaDB|MongoDB|DevOps|GitOps|LinkedIn|YouTube|WordPress|RedHat|CentOS|"
    "FreeBSD|NetApp|VMware|McAfee|LibreOffice"
)
CODE_TOKEN = re.compile(
    "|".join(
        [
            # --force, -n, --dry-run=client, and a flag mangled into —force
            r"(?<![\w-])(?:--?|[–—])[A-Za-z][\w-]*(?:=[^\s,;]+)?",
            # /etc/hosts, ~/.kube/config, ./run.sh
            r"(?<![\w/.~-])(?:~|\.{1,2})?/[\w.@%+<>{}$-]+(?:/[\w.@%+<>{}$-]*)*",
            # install-config.yaml, manifests/cluster.yml
            rf"(?<![\w/.-])[\w-]+(?:/[\w.-]+)*\.(?:{FILE_EXT})\b",
            # $HOME, ${KUBECONFIG}
            r"\$\{?[A-Za-z_]\w*\}?",
            # <namespace>, {product-version}
            r"<[A-Za-z][\w.-]*>|\{[A-Za-z][\w.-]*\}",
            # replicas=3
            r"\b\w+=[^\s,;]+",
            # max_pods, maxUnavailable, spec.template.spec
            r"\b\w*_\w+\b|\b[a-z]+[A-Z]\w*\b|\b[a-z]\w+(?:\.[a-z]\w+)+\b",
            # MachineConfigPool, ImageStream (Kubernetes kinds)
            rf"\b(?!(?:{PRODUCT_NAMES})\b)(?:[A-Z][a-z]+){{2,}}[A-Za-z]*\b",
            # openshift-logging, kube-system
            r"\b(?:openshift|kube|olm|ocp|rhel)-[a-z0-9]+(?:-[a-z0-9]+)*\b",
            # ubi9, x86, s390x, arm64, IPv6, v1beta1 (but not the version v1.2.3)
            r"(?<![\w-])(?![vV]\d+(?:\.\d+)*\b)[A-Za-z]+\d[A-Za-z\d]*\b(?![.-]\w)",
        ]
    )
)

# Commands written in prose without backticks: "Run oc adm upgrade to start."
# A known CLI after run/use/... or "$ ", then its arguments up to an ordinary word.
# ponytail: lexicon heuristic, extend CLI when a docs set uses other tools
CLI = (
    "oc|kubectl|podman|docker|helm|openshift-install|systemctl|journalctl|sudo|"
    "dnf|yum|rpm|curl|wget|git|ssh|scp|ansible-playbook|virtctl|crictl|etcdctl|"
    "skopeo|buildah|tkn|rosa"
)
STOP_WORDS = (
    "to|and|or|then|the|a|an|for|in|on|with|from|if|when|until|after|before|as|"
    "so|but|again|first|now|once|which|that|this|while|because|is|are|was|will|"
    "command|tool|cli|binary|client|utility"
)
ARGUMENT = r"--?[\w-]+(?:=[^\s,;]+)?|<[\w.-]+>|[a-z0-9][\w./:=@~-]*"
COMMAND = re.compile(
    r"(?P<lead>(?:^|\$\s+|\b(?i:run|running|use|using|execute|executing|enter|type|"
    r"invoke)\s+)(?i:the\s+)?)"
    rf"(?P<command>\b(?:{CLI})\b(?:[ \t]+(?!(?i:{STOP_WORDS})\b)(?:{ARGUMENT}))*)",
    re.M,
)
# Kebab-case resource names in prose: "the openshift-logging namespace",
# "a project named my-app". English compounds next to the same nouns are not names.
RESOURCE_NOUNS = (
    "namespace|project|operator|pod|deployment|daemon ?set|stateful ?set|service|"
    "secret|config ?map|route|subscription|channel|catalog source|image stream|"
    "machine ?set|machine config pool|storage ?class|pvc|service account|role|"
    "role ?binding"
)
COMPOUNDS = (
    "third-party|built-in|well-known|cluster-wide|add-on|open-source|read-only|"
    "read-write|self-signed|self-managed|single-node|multi-node|multi-tenant|"
    "up-to-date|long-running|user-defined|user-provided|pre-installed|"
    "high-availability|default-only|non-default|custom-built|red-hat-provided"
)
RESOURCE_NAME = re.compile(
    rf"(?P<lead>\b(?i:{RESOURCE_NOUNS}|named|called)[ \t]+)"
    rf"(?!(?:{COMPOUNDS})\b)(?P<named>[a-z0-9]+(?:-[a-z0-9]+)+)\b"
    rf"|(?<![\w-])(?!(?:{COMPOUNDS})\b)(?P<name>[a-z0-9]+(?:-[a-z0-9]+)+)"
    rf"(?=[ \t]+(?i:{RESOURCE_NOUNS})\b)"
)

# --- numbers -------------------------------------------------------------------

# Only exact number words. Vague ones (a few, several, twice) stay words, so
# "3 replicas" → "a few replicas" is reported.
ONES = "one two three four five six seven eight nine".split()
SMALL = ["zero", *ONES] + (
    "ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen "
    "nineteen twenty"
).split()
TENS = "twenty thirty forty fifty sixty seventy eighty ninety".split()
WORD_VALUE = {w: n for n, w in enumerate(SMALL)}
WORD_VALUE |= {w: 20 + 10 * n for n, w in enumerate(TENS)}
NUMBER_WORD = re.compile(
    rf"\b(?:({'|'.join(TENS)})[\s-]({'|'.join(ONES)})|({'|'.join(WORD_VALUE)}))\b",
    re.I,
)
# "one" is a pronoun after these words ("no one", "a new one", "the one that
# failed") and before "of"/"another" ("one of the nodes").
PRONOUN_ONE_AFTER = set(
    "a an another any each every no some the this that which new old other same "
    "last first next previous existing current only right wrong latest default".split()
)
PRONOUN_ONE_BEFORE = re.compile(r"\s+(?:of|another)\b", re.I)

# Spelling variants of one unit. Never a conversion: Gi ≠ G, m (milli) ≠ min.
UNITS = {
    "ms": "ms|msec|millisecond|milliseconds",
    "s": "s|sec|secs|second|seconds",
    "min": "min|mins|minute|minutes",
    "h": "h|hr|hrs|hour|hours",
    "day": "day|days",
    "week": "week|weeks",
    "%": "%|percent|per cent",
    "KiB": "Ki|KiB",
    "MiB": "Mi|MiB",
    "GiB": "Gi|GiB",
    "TiB": "Ti|TiB",
    "KB": "KB|kilobyte|kilobytes",
    "MB": "MB|megabyte|megabytes",
    "GB": "GB|gigabyte|gigabytes",
    "TB": "TB|terabyte|terabytes",
}
UNIT_OF = {
    alias.lower(): unit
    for unit, aliases in UNITS.items()
    for alias in aliases.split("|")
}
UNIT_ALTERNATIVES = "|".join(sorted(map(re.escape, UNIT_OF), key=len, reverse=True))

# "at least 3" and "3" are different facts; "at least 3" and "3 or more" are not.
COMPARATORS = {
    "≥": r"at least|no fewer than|no less than|not less than|no earlier than|"
    r"(?:a )?minimum(?: of)?|>=|≥",
    "≤": r"at most|up to|no more than|not more than|no later than|"
    r"(?:a )?maximum(?: of)?|<=|≤",
    ">": r"more than|greater than|over|above|exceed(?:s|ing)?|>",
    "<": r"less than|fewer than|under|below|<",
}
NUMBER = re.compile(
    rf"(?:(?P<comparator>{'|'.join(COMPARATORS.values())})\s*)?"
    # 4.14, v1.2.3-rc.1, 1,000, .5, 2nd
    rf"(?<![\w.])(?P<spelled>{SPELLED})?(?:v(?=\d))?"
    r"(?P<integer>\d{1,3}(?:,\d{3})+|\d+|(?=\.\d))"
    r"(?P<fraction>(?:\.\d+)*(?:-(?:rc|alpha|beta|ec|pre|dev)\.?\d*)?)"
    r"(?:st|nd|rd|th)?"
    # 30 minutes, 2Gi, 50 %, or any attached suffix: 100m, 4x
    rf"(?:[\s-]?(?P<unit>{UNIT_ALTERNATIVES})(?![\w%])|(?P<suffix>[a-z]+))?"
    r"(?P<or_more>\s+or\s+(?:more|later|newer|higher|greater|above)\b|\+(?!\w))?"
    r"(?P<or_less>\s+or\s+(?:less|fewer|earlier|older|lower|below)\b)?"
    r"(?!\w)",
    re.I,
)

# --- negation ------------------------------------------------------------------

CONTRACTIONS = [
    (re.compile(r"\bwon't\b", re.I), "will not"),
    (re.compile(r"\bshan't\b", re.I), "shall not"),
    (re.compile(r"\bcan't\b|\bcannot\b", re.I), "can not"),
    (re.compile(r"n't\b", re.I), " not"),
]
# Fixed phrases that contain a cue but don't negate anything (NegEx "pseudo"
# triggers that are polarity-neutral). Comparators belong to the number check.
PSEUDO_NEGATION = re.compile(
    r"(?<![\w-])(?:not only|whether or not|no matter|not to mention|nothing but|"
    r"none other than|no doubt|(?:do not|never) forget|"
    r"(?:no|not) (?:more|fewer|less|later|earlier) than)(?![\w-])",
    re.I,
)
NEGATION = re.compile(
    r"(?<![\w-])(not|no|never|none|nothing|nobody|nowhere|neither|nor|without)(?![\w-])"
    r"(?=(\s+\w+)?)",
    re.I,
)
# Negation by vocabulary, counted together with NEGATION: "cannot" → "is unable
# to" keeps the count, dropping "cannot" altogether does not.
LEXICAL_NEGATION = re.compile(
    r"(?<![\w-])(?:fail(?:s|ed|ing|ures?)?(?: to)?|unable to|lacks?|lacking|absent|"
    r"unless|otherwise|rather than|instead of|prevents?|prohibits?|disallows?|"
    r"avoid(?:s|ing)?|un(?:supported|available|reachable|healthy|schedulable|ready)|"
    r"in(?:valid|secure|correct|compatible|accessible|sufficient))(?![\w-])",
    re.I,
)
# Words that flip the meaning without any "not": (positive, negative) sides.
OPPOSITES = [
    ("enable|turn on|switch on", "disable|turn off|switch off"),
    ("allow|permit", "deny|disallow|block|forbid"),
    ("include", "exclude"),
    ("increase|raise", "decrease|lower|reduce"),
    ("higher|greater|larger", "lower|smaller"),
    ("add", "remove|delete"),
    ("true", "false"),
    ("start", "stop"),
    ("accept", "reject"),
    ("public", "private"),
    ("ingress", "egress"),
    ("inbound", "outbound"),
    ("succeed|pass", "fail"),
    ("success", "failure"),
    ("maximum", "minimum"),
    ("upgrade", "downgrade"),
    ("encrypt", "decrypt"),
    ("connect", "disconnect"),
    ("attach", "detach"),
    ("internal", "external"),
    ("read-only", "read-write"),
    ("synchronous", "asynchronous"),
    ("show", "hide"),
    ("required", "optional"),
]
# supported → unsupported, valid → invalid, secure → insecure, root → non-root
NEGATING_PREFIXES = ("non-", "non", "un", "in", "im", "ir", "il", "dis")
WORD = re.compile(r"[a-z]+(?:-[a-z]+)*")

# --- requirement strength --------------------------------------------------------

# Alternation order matters: "not required" must match as optional before
# "required" can match as required (NegEx longest-match-first).
STRENGTH = {
    "optional": (
        r"optional(?:ly)?|not (?:required|necessary|mandatory|needed)|unnecessary|"
        r"no (?:[\w-]+ ){0,3}(?:is|are) (?:required|necessary|needed)|"
        r"no need to|need not|(?:do|does|did) not (?:need(?: to)?|have to)|"
        r"(?:might|may|could) (?:need|have) to|"
        r"you (?:can|may)(?! not\b)|can be|may(?! not\b)|"
        r"if (?:needed|necessary|required|desired|applicable)|as needed"
    ),
    "recommended": (
        r"not recommended|should(?: not)?|ought to|recommend(?:s|ed|ations?)?|"
        r"suggest(?:s|ed)?|advis(?:e|ed|able)|best practices?|prefer(?:ably|red)?|"
        r"ideally|you might want to"
    ),
    # Requirement stated as a fact: dropping it weakens the text.
    "required": r"required|requires?|mandatory|necessary|(?<!if you )needs?(?! to\b)",
    # Requirement stated as an order: "You must back up" means the same as
    # "Back up", so these alone are not reported. Same for "make sure".
    "imperative": r"must(?: not)?|shall(?: not)?|needs? to|ha(?:ve|s) to",
    # How certain the text is: "the node will restart" → "might restart".
    "possible": r"might|could|possibly|perhaps|potentially",
}
MODAL = re.compile(
    # (?![\w-]): "must-gather" is a tool, not a requirement
    "|".join(
        rf"(?<![\w-])(?P<{level}>{words})(?![\w-])" for level, words in STRENGTH.items()
    ),
    re.I,
)
# RFC 8174: the keywords are normative only in capitals, so MUST → must matters.
BCP14 = re.compile(
    r"\b(?:MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|NOT RECOMMENDED|"
    r"RECOMMENDED|REQUIRED|MAY|OPTIONAL)\b"
)

# --- scope -----------------------------------------------------------------------

# "Use --force only when the node is unreachable" → "Use --force when ..."
# ("not only ... but also" is not a restriction)
RESTRICTOR = re.compile(
    r"(?<![\w-])(?<!not )(?:only|solely|exclusively)(?![\w-])", re.I
)
# "on all control plane nodes" → "on a control plane node". Dropping "all" alone
# ("check all logs" → "check the logs") is normal, so the noun has to come back
# with a/one/some in front of it.
UNIVERSAL = re.compile(r"(?<![\w-])(?:all|every|each)\s+(?:the\s+)?([a-z][\w-]*)", re.I)
# "Back up before you update" → "After you update, back up"
ORDER = [("before|prior to", "after")]

# --- length --------------------------------------------------------------------

# Paraphrase corpora keep the shorter text above ~66-75 % of the longer one
# (MSRP, ASSET); below that the rewrite is more of a summary.
SHORTER_THAN = 0.75
LONGER_THAN = 1.5
MIN_WORDS_FOR_RATIO = 30
MIN_WORDS_CHANGED = 10
SHORT_TEXT_SHORTER_THAN = 0.6
# A list item counts as dropped when under half of its words are left anywhere.
ITEM_KEPT = 0.5
FUNCTION_WORDS = set(
    "the and for with from that this then into your you are was were will can "
    "all any has have had not but its it's their there when which while".split()
)


def compare(original: str, rewritten: str) -> list[Issue]:
    """Return what `rewritten` lost or changed compared to `original`, errors first."""
    o, r = _Facts(_normalize(original)), _Facts(_normalize(rewritten))
    formatting_lost = _match_formatting(o, r)
    o.extract_prose_facts()
    r.extract_prose_facts()
    issues = [
        *_code_issues(o, r, formatting_lost),
        *_diff("url", o.links, r.links, "Links changed"),
        *_number_issues(o, r),
        *_negation_issues(o, r),
        *_modality_issues(o, r),
        *_scope_issues(o, r),
        *_length_issues(o, r),
    ]
    return sorted(issues, key=lambda issue: issue.severity != "error")


class _Facts:
    """Facts of one text. Every extraction masks what it found in `prose`."""

    def __init__(self, text: str):
        self.text = text
        self.block_lines: list[str] = []
        self.formatted: list[str] = []
        self.links: list[str] = []
        self.code: list[str] = []
        self.prose = BLOCK.sub(self._take_block, text)
        self.prose = INLINE_CODE.sub(self._take_inline, self.prose)
        self.list_items = LIST_ITEM.findall(self.prose)
        # Renumbered or bulleted steps are not changed numbers.
        self.prose = LIST_ITEM.sub(MASK + r" \1", self.prose)

    def _take_block(self, match: re.Match) -> str:
        lines = [line.strip() for line in match[2].splitlines() if line.strip()]
        self.block_lines += lines
        self.formatted += lines
        return MASK

    def _take_inline(self, match: re.Match) -> str:
        code = match[1].strip()
        self.formatted.append(PASSTHROUGH.sub(r"\1", code).strip())
        return MASK

    def mask_verbatim(self, item: str) -> bool:
        """Mask one plain-text occurrence of `item` in prose, if there is one."""
        self.prose, found = _verbatim(item).subn(MASK, self.prose, count=1)
        return bool(found)

    def extract_prose_facts(self) -> None:
        self.prose = URL.sub(self._take_link, self.prose)
        self.prose = EMAIL.sub(self._take_link, self.prose)
        self.code = list(self.formatted)
        self.prose = COMMAND.sub(self._take_command, self.prose)
        self.prose = RESOURCE_NAME.sub(self._take_resource, self.prose)
        tokens = CODE_TOKEN.findall(self.prose)
        self.code += [_strip_trailing(token) for token in tokens]
        self.prose = CODE_TOKEN.sub(MASK, self.prose)

    def _take_command(self, match: re.Match) -> str:
        self.code.append(_strip_trailing(match["command"]))
        return match["lead"] + MASK

    def _take_resource(self, match: re.Match) -> str:
        self.code.append(match["named"] or match["name"])
        return (match["lead"] or "") + MASK

    def _take_link(self, match: re.Match) -> str:
        link = _strip_trailing(match[0])
        self.links.append(_normalize_link(link))
        return MASK + match[0][len(link) :]

    def numbers(self) -> tuple[list[str], list[str]]:
        """All numbers, and those of them that were a bare number word ("two")."""
        prose = NUMBER_WORD.sub(_word_to_digits, self.prose)
        numbers, spelled = [], []
        for match in NUMBER.finditer(prose):
            numbers.append(_number(match))
            plain = not (match["comparator"] or match["unit"] or match["suffix"])
            if match["spelled"] and plain:
                spelled.append(numbers[-1])
        return numbers, spelled

    def expanded_prose(self) -> str:
        """Prose with contractions written out: don't → do not."""
        prose = self.prose
        for pattern, replacement in CONTRACTIONS:
            prose = pattern.sub(replacement, prose)
        return prose

    def negations(self) -> list[str]:
        """Each negation cue with the word after it, e.g. "not restart"."""
        prose = PSEUDO_NEGATION.sub(MASK, self.expanded_prose())
        return [
            " ".join(f"{m[1]}{m[2] or ''}".lower().split())
            for m in NEGATION.finditer(prose)
        ]

    def lexical_negations(self) -> list[str]:
        return [m[0].lower() for m in LEXICAL_NEGATION.finditer(self.expanded_prose())]

    def words(self) -> Counter:
        return Counter(WORD.findall(self.prose.lower()))

    def modals(self) -> dict[str, list[str]]:
        found = {level: [] for level in STRENGTH}
        for match in MODAL.finditer(self.expanded_prose()):
            words = " ".join(match[0].lower().split())
            # "You can enable X" and "X can be enabled" offer the same option.
            found[match.lastgroup].append("you can" if words == "can be" else words)
        return found

    def word_count(self) -> int:
        return len(re.findall(r"\w+(?:['-]\w+)*", self.prose))


def _match_formatting(o: _Facts, r: _Facts) -> list[str]:
    """Code that only lost (or gained) its backticks or fence is the same code.

    Returns the code whose formatting the rewrite removed.
    """
    lost = []
    for item in Counter(o.formatted) - Counter(r.formatted):
        if r.mask_verbatim(item):
            r.formatted.append(item)
            lost.append(item)
    for item in Counter(r.formatted) - Counter(o.formatted):
        if o.mask_verbatim(item):
            o.formatted.append(item)
    return lost


def _word_to_digits(match: re.Match) -> str:
    tens, ones, word = match[1], match[2], match[3]
    if tens:
        return SPELLED + str(WORD_VALUE[tens.lower()] + WORD_VALUE[ones.lower()])
    if word.lower() == "one":
        before = re.findall(
            r"\w+", match.string[max(0, match.start() - 20) : match.start()]
        )
        if (
            before and before[-1].lower() in PRONOUN_ONE_AFTER
        ) or PRONOUN_ONE_BEFORE.match(match.string, match.end()):
            return word
    return SPELLED + str(WORD_VALUE[word.lower()])


def _number(match: re.Match) -> str:
    """4.10 stays 4.10 (versions), 1,000 → 1000, at least 3 minutes → ≥3 min."""
    value = (match["integer"].replace(",", "") or "0") + match["fraction"].lower()
    if match["comparator"]:
        value = _comparator(match["comparator"]) + value
    elif match["or_more"]:
        value = "≥" + value
    elif match["or_less"]:
        value = "≤" + value
    if match["unit"]:
        return f"{value} {UNIT_OF[match['unit'].lower()]}"
    if match["suffix"]:
        return f"{value} {match['suffix']}"
    return value


def _comparator(text: str) -> str:
    text = " ".join(text.lower().split())
    matches = (
        symbol for symbol, words in COMPARATORS.items() if re.fullmatch(words, text)
    )
    return next(matches, "")


def _strip_trailing(text: str) -> str:
    """Drop sentence punctuation and an unbalanced ")" from the end of a token."""
    while True:
        stripped = text.rstrip(TRAILING)
        if stripped.endswith(")") and stripped.count(")") > stripped.count("("):
            stripped = stripped[:-1]
        if stripped == text:
            return text
        text = stripped


def _normalize_link(link: str) -> str:
    scheme, separator, rest = link.partition("://")
    if not separator:
        return link.lower().rstrip("/")
    host, slash, path = rest.partition("/")
    return f"{scheme.lower()}://{host.lower()}{slash}{path}".rstrip("/")


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFC", text).translate(CHARACTERS)


def _diff(
    kind: Kind,
    original: list[str],
    rewritten: list[str],
    message: str,
    severity: Severity = "error",
) -> list[Issue]:
    missing = list((Counter(original) - Counter(rewritten)).elements())
    added = list((Counter(rewritten) - Counter(original)).elements())
    if not missing and not added:
        return []
    return [Issue(kind, severity, message, missing, added)]


def _verbatim(item: str) -> re.Pattern:
    """`item` as a whole token: --force does not match inside --force-conflicts."""
    return re.compile(rf"(?<![\w-]){re.escape(item)}(?![\w-])(?!\.\w)")


def _not_in(items: list[str], text: str) -> list[str]:
    """Items that occur fewer times in `text` than in `items`.

    Matching against the whole other text, not its extracted tokens, means the
    same code found by different rules on each side (`oc adm upgrade --force`
    vs. "run oc adm upgrade with --force") still counts as present.
    """
    return [
        item
        for item, count in Counter(items).items()
        for _ in range(count - min(count, len(_verbatim(item).findall(text))))
    ]


def _code_issues(o: _Facts, r: _Facts, formatting_lost: list[str]) -> list[Issue]:
    issues = []
    missing, added = _not_in(o.code, r.text), _not_in(r.code, o.text)
    if missing or added:
        message = "Code, commands, paths or flags changed"
        issues.append(Issue("code", "error", message, missing, added))
    elif (
        o.block_lines
        and Counter(o.block_lines) == Counter(r.block_lines)
        and o.block_lines != r.block_lines
    ):
        issues.append(Issue("code", "error", "Code block lines were reordered"))
    elif (
        len(o.list_items) >= 2
        and Counter(o.formatted) == Counter(r.formatted)
        and o.formatted != r.formatted
    ):
        message = "Steps with code are in a different order"
        issues.append(Issue("code", "warning", message))
    if formatting_lost:
        message = "Code formatting was removed, the code itself is unchanged"
        issues.append(Issue("code", "warning", message, missing=formatting_lost))
    return _merge(issues)


def _number_issues(o: _Facts, r: _Facts) -> list[Issue]:
    (numbers_o, _), (numbers_r, spelled_r) = o.numbers(), r.numbers()
    missing = Counter(numbers_o) - Counter(numbers_r)
    added = Counter(numbers_r) - Counter(numbers_o)
    if not missing:
        # "Draining does two things: ..." adds a count for structure, it does not
        # change one. A replaced number ("three" → "two") still has a missing side.
        added -= Counter(spelled_r)
    if not missing and not added:
        return []
    message = "Numbers changed"
    return [
        Issue(
            "number", "error", message, list(missing.elements()), list(added.elements())
        )
    ]


def _negation_issues(o: _Facts, r: _Facts) -> list[Issue]:
    """Negation count and opposite words, judged together.

    Polarity = negation cues + words on the negative side of an opposite pair.
    "not available" → "unavailable" keeps it (a warning), "available" →
    "unavailable" or a dropped "not" changes it (an error).
    """
    flips = _flips(o, r, _opposite_pairs(o.words() | r.words()))
    flipped = tuple(word for flip in flips for word in flip[:2])

    def lexical(facts: _Facts) -> list[str]:
        # "supported → unsupported" is counted once, as a flip.
        return [w for w in facts.lexical_negations() if not w.startswith(flipped)]

    cues_o, cues_r = o.negations() + lexical(o), r.negations() + lexical(r)
    strict_changed = len(o.negations()) != len(r.negations())
    to_negative = sum(direction for _, _, direction in flips)
    delta = len(cues_r) - len(cues_o)
    if not delta and not strict_changed and not flips:
        return []
    missing, added = _diff_lists(cues_o, cues_r)
    missing += [lost for lost, _, _ in flips]
    added += [gained for _, gained, _ in flips]
    if delta + to_negative == 0:
        message = "Negation is worded differently (e.g. not available → unavailable)"
        return [Issue("negation", "warning", message, missing, added)]
    reasons = []
    if delta:
        reasons.append(f"number of negations changed: {len(cues_o)} → {len(cues_r)}")
    if flips:
        pairs = ", ".join(f"{lost} → {gained}" for lost, gained, _ in flips)
        reasons.append(f"opposite word used: {pairs}")
    return [Issue("negation", "error", "; ".join(reasons).capitalize(), missing, added)]


def _opposite_pairs(words: Counter) -> list[tuple[str, str, re.Pattern, re.Pattern]]:
    """OPPOSITES plus prefix pairs found in the texts: supported / unsupported."""
    pairs = [(a, b, _word_forms(a), _word_forms(b)) for a, b in OPPOSITES]
    for word in words:
        for prefix in NEGATING_PREFIXES:
            base = word.removeprefix(prefix)
            if base != word and len(base) >= 4:
                pairs.append((base, word, _exact(base), _exact(word)))
                break
    return pairs


def _flips(o: _Facts, r: _Facts, pairs: list) -> list[tuple[str, str, int]]:
    """Pairs where one side's count fell while the other side's count rose.

    Requiring both directions keeps "install" from pairing with "stall": a
    rewrite would have to drop one and add the other. Returns (lost, gained,
    +1 if the text moved to the negative side, -1 if away from it).
    """
    text_o, text_r = o.prose.lower(), r.prose.lower()
    flips = []
    for positive, negative, forms_p, forms_n in pairs:
        change_p = len(forms_p.findall(text_r)) - len(forms_p.findall(text_o))
        change_n = len(forms_n.findall(text_r)) - len(forms_n.findall(text_o))
        if change_p < 0 < change_n:
            flips.append((positive.split("|")[0], negative.split("|")[0], 1))
        elif change_n < 0 < change_p:
            flips.append((negative.split("|")[0], positive.split("|")[0], -1))
    return flips


def _word_forms(alternatives: str) -> re.Pattern:
    """enable|turn on → enable, enables, enabled, enabling, turns on, turned on, ..."""
    forms = []
    for phrase in alternatives.split("|"):
        first, _, rest = phrase.partition(" ")
        inflected = "|".join(sorted(_forms(first), key=len, reverse=True))
        forms.append(f"(?:{inflected})" + (f" {re.escape(rest)}" if rest else ""))
    return re.compile(rf"(?<![\w-])(?:{'|'.join(forms)})(?![\w-])")


def _exact(word: str) -> re.Pattern:
    return re.compile(rf"(?<![\w-]){re.escape(word)}(?![\w-])")


def _forms(word: str) -> set[str]:
    """enable → enable, enables, enabled, enabling; stop → stopped, stopping."""
    stem = word.removesuffix("e")
    forms = {
        word,
        word + "s",
        word + "es",
        word + "d",
        word + "ed",
        stem + "ing",
        stem + "ed",
    }
    if word.endswith("y"):
        forms |= {word[:-1] + "ies", word[:-1] + "ied"}
    if re.search(r"[^aeiou][aeiou][bdgmnprt]$", word):
        forms |= {word + word[-1] + "ed", word + word[-1] + "ing"}
    return forms


def _modality_issues(o: _Facts, r: _Facts) -> list[Issue]:
    original, rewritten = o.modals(), r.modals()
    # Rewrites add "you can" as filler ("you can see the status"). It matters when
    # it is lost ("You can configure X" → "Configure X" turns an option into an
    # order) or when it replaced a requirement ("you must" → "you can").
    weakened = any(
        len(rewritten[level]) < len(original[level])
        for level in ("required", "imperative")
    )
    surplus = rewritten["optional"].count("you can") - original["optional"].count(
        "you can"
    )
    for _ in range(0 if weakened else surplus):
        rewritten["optional"].remove("you can")
    changed = [
        level for level in STRENGTH if len(original[level]) != len(rewritten[level])
    ]
    reported = [level for level in changed if level != "imperative"]
    reasons = [
        f"{level} {len(original[level])} → {len(rewritten[level])}"
        for level in reported
    ]
    words_o = (
        [word for level in changed for word in original[level]] if reported else []
    )
    words_r = (
        [word for level in changed for word in rewritten[level]] if reported else []
    )
    keywords_o, keywords_r = BCP14.findall(o.prose), BCP14.findall(r.prose)
    if keywords_o and Counter(keywords_o) != Counter(keywords_r):
        reasons.append("RFC 2119 keywords in capitals changed")
        words_o += keywords_o
        words_r += keywords_r
    if not reasons:
        return []
    missing, added = _diff_lists(words_o, words_r)
    message = f"Requirement strength changed ({', '.join(reasons)})"
    return [Issue("modality", "warning", message, missing, added)]


def _scope_issues(o: _Facts, r: _Facts) -> list[Issue]:
    reasons, missing, added = [], [], []
    only_o = [m[0].lower() for m in RESTRICTOR.finditer(o.prose)]
    only_r = [m[0].lower() for m in RESTRICTOR.finditer(r.prose)]
    if len(only_o) != len(only_r):
        reasons.append(
            f"restriction ({'/'.join(sorted(set(only_o + only_r)))}) changed"
        )
        lost, gained = _diff_lists(only_o, only_r)
        missing, added = missing + lost, added + gained
    for match in UNIVERSAL.finditer(o.prose):
        stem = re.escape(match[1][:4].lower())
        if not re.search(
            rf"\b(?:all|every|each|any)\s+(?:the\s+)?{stem}", r.prose, re.I
        ) and (
            re.search(
                rf"\b(?:a|an|one|some|single)\s+(?:[\w-]+\s+)?{stem}", r.prose, re.I
            )
        ):
            reasons.append(f"'{match[0]}' became one or some")
            missing.append(match[0].lower())
    order = [(a, b, _word_forms(a), _word_forms(b)) for a, b in ORDER]
    for lost, gained, _ in _flips(o, r, order):
        reasons.append(f"order word changed: {lost} → {gained}")
        missing.append(lost)
        added.append(gained)
    if not reasons:
        return []
    message = "Scope or order changed (" + "; ".join(reasons) + ")"
    return [Issue("scope", "warning", message, missing, added)]


def _length_issues(o: _Facts, r: _Facts) -> list[Issue]:
    issues = []
    dropped = _dropped_items(o.list_items, r.list_items, r.text)
    if dropped:
        message = f"List item dropped ({len(o.list_items)} → {len(r.list_items)} items)"
        issues.append(Issue("length", "error", message, missing=dropped))
    before, after = o.word_count(), r.word_count()
    reasons = []
    if before and (
        (before >= MIN_WORDS_FOR_RATIO and after < before * SHORTER_THAN)
        or (
            before - after >= MIN_WORDS_CHANGED
            and after < before * SHORT_TEXT_SHORTER_THAN
        )
    ):
        reasons.append(
            f"much shorter: {after} of {before} words ({after / before:.0%})"
        )
    if before and after > before * LONGER_THAN and after - before >= MIN_WORDS_CHANGED:
        reasons.append(
            f"much longer: {after} words instead of {before}, content may be added"
        )
    if (
        not dropped
        and len(o.list_items) >= 2
        and len(r.list_items) != len(o.list_items)
    ):
        reasons.append(f"list items {len(o.list_items)} → {len(r.list_items)}")
    if reasons:
        issues.append(Issue("length", "warning", "Rewrite is " + "; ".join(reasons)))
    return issues


def _dropped_items(
    items: list[str], items_left: list[str], rewritten: str
) -> list[str]:
    """Steps that are gone: fewer list items, and their words are not elsewhere.

    At most as many as the list shrank by, the ones with the fewest words left.
    """
    fewer = len(items) - len(items_left)
    if len(items) < 2 or fewer <= 0:
        return []
    kept_words = set(re.findall(r"[a-z0-9]+", rewritten.lower()))
    candidates = []
    for item in items:
        words = set(re.findall(r"[a-z0-9]{3,}", item.lower())) - FUNCTION_WORDS
        kept = len(words & kept_words) / len(words) if len(words) >= 2 else 1
        if kept < ITEM_KEPT:
            candidates.append((kept, item.replace(MASK, "…").strip()))
    return [item for _, item in sorted(candidates)[:fewer]]


def _diff_lists(
    original: list[str], rewritten: list[str]
) -> tuple[list[str], list[str]]:
    missing = list((Counter(original) - Counter(rewritten)).elements())
    added = list((Counter(rewritten) - Counter(original)).elements())
    return missing, added


def _merge(issues: list[Issue]) -> list[Issue]:
    """One issue per severity, so a kind is reported once per severity."""
    merged: dict[Severity, Issue] = {}
    for issue in issues:
        if issue.severity not in merged:
            merged[issue.severity] = issue
            continue
        target = merged[issue.severity]
        target.message += f"; {issue.message}"
        target.missing += issue.missing
        target.added += issue.added
    return list(merged.values())

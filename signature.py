import re

CONNECTOR = r'[\s\S]{0,120}'
IDENT = r'[A-Za-z_]\w*'
TOKEN_RE = re.compile(
    r'"(?:\\.|[^"])*"|\'(?:\\.|[^\'])*\'|[A-Za-z_]\w*|\d+|\s+|.'
)
KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof",
    "NULL", "true", "false"
}


def loosen(line):
    tokens = TOKEN_RE.findall(line.strip())
    out = []

    def next_non_space(index):
        for token in tokens[index + 1:]:
            if not token.isspace():
                return token
        return ""

    for index, token in enumerate(tokens):
        if token.isspace():
            out.append(r'\s*')
        elif re.fullmatch(r'\d+', token):
            out.append(r'\d+')
        elif re.fullmatch(r'[A-Za-z_]\w*', token):
            if token in KEYWORDS or token.isupper() or next_non_space(index) == "(":
                out.append(re.escape(token))
            else:
                out.append(IDENT)
        else:
            out.append(re.escape(token))

    return "".join(out)


def has_trigram(pattern):
    s = re.sub(r'\\[wWdDsS]', '', pattern)
    s = re.sub(r'\[\\s\\S\]\{[^}]+\}', '', s)
    return bool(re.search(r'[A-Za-z0-9_()\[\];,<>=!\-*&]{3,}', s))


def generate_signatures(removed):
    out = []
    for line in removed:
        p = loosen(line)
        if p and len(p) > 10:
            out.append(p)
    return out


def generate_signatures_v2(patch):
    sigs = []
    seen = set()
    for hunk in patch.get("hunks", []):
        removed = hunk.get("removed", [])
        added = hunk.get("added", [])
        if not removed:
            continue

        if len(removed) >= 2:
            frags = [loosen(l) for l in removed[:6] if loosen(l)]
            if len(frags) >= 2:
                vuln = CONNECTOR.join(frags)
                if has_trigram(vuln):
                    fix_frags = [loosen(l) for l in added[:4] if loosen(l)]
                    fix = CONNECTOR.join(fix_frags) if fix_frags else ""
                    key = (vuln, fix)
                    if key in seen:
                        continue
                    seen.add(key)
                    sigs.append({
                        "vuln": vuln,
                        "fix": fix,
                        "multi": True,
                        "confidence": "high" if len(re.findall(r'[A-Za-z0-9]{2,}', vuln)) >= 3 else "medium"
                    })

        for line in removed[:4]:
            p = loosen(line)
            if not p or not has_trigram(p):
                continue
            fix_frags = [loosen(l) for l in added[:2] if loosen(l)]
            fix = CONNECTOR.join(fix_frags) if fix_frags else ""
            key = (p, fix)
            if key in seen:
                continue
            seen.add(key)
            sigs.append({
                "vuln": p,
                "fix": fix,
                "multi": False,
                "confidence": "medium"
            })

    return sigs

import re


def normalize(line):
    return re.sub(r'\s+', ' ', line.strip())


def extract_func(line):
    m = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*)\)', line)
    if m:
        return m.group(1), m.group(2)
    return None, None


def build_regex(line):
    line = normalize(line)
    func, args = extract_func(line)

    if func:
        parts = args.split(',')

        gen = []
        for p in parts:
            p = p.strip()

            if '"' in p:
                gen.append(r'"[^"]*"')
            elif re.match(r'\d+', p):
                gen.append(r'\d+')
            else:
                gen.append(r'[^,]+')

        args_pattern = r'\s*,\s*'.join(gen)

        return rf"{func}\s*\(\s*{args_pattern}\s*\)"

    # fallback
    line = re.escape(line)
    return line.replace(r'\ ', r'\s*')


def generate_signatures(lines):
    return [build_regex(l) for l in lines]

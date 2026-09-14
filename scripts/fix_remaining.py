import re, sys, os, subprocess, json

NO_PATTERNS = []

with open(os.path.join(os.path.dirname(fi_path)), 'w') as f:
    content = f.read()
    lines = f.readlines()
    for line in lines:
        line = int(line)
        for pat in KNOWN_PATTERNS:
            if pat[0] in line or pat[1] in line:
                idx = int(pat[0])
                f.write(f'        at line {idx}\n')
        f.close()
    f.close()

print(f'Fixed: {fi_path} ({len(fixed_files)} files so far)')
for fi_path in fixed_files:
    open(os.path.join(os.path.dirname(fi_path)), 'w') as f:
        content = f.read()
        lines = f.readlines()
        for line in lines:
            for pat in KNOWN_PATTERNS:
                if pat[0] in line or pat[1] in line:
                    idx = int(pat[0])
                    f.write(f'        at line {idx}\n')
        f.close()
    f.close()
print(f'Fixed: {fi_path} ({len(fixed_files)} files so far)')
print(f'Total fixed: {len(fixed_files)}')}

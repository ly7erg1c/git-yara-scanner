#!/usr/bin/env python3
"""Command-line tool to clone git repositories, scan them with YARA rules, and output results."""

import argparse
import subprocess
import os
import re
import sys
import shutil
import json
import csv
try:
    import requests
except ImportError:
    requests = None
import random
import datetime
from random_new_repos import get_new_repos
try:
    from tqdm import tqdm
except ImportError:
    tqdm = lambda iterable, **kwargs: iterable
import time

# Load configuration and set GitHub token from config file if present
try:
    import yaml
except ImportError:
    yaml = None
CONFIG = {}
for cfg_file in ('config.yaml', 'config.yml'):
    if os.path.exists(cfg_file):
        if yaml:
            with open(cfg_file, 'r') as f:
                try:
                    CONFIG = yaml.safe_load(f) or {}
                except Exception as e:
                    print(f"Warning: failed to parse config file {cfg_file}: {e}", file=sys.stderr)
        else:
            print("Warning: PyYAML not installed; cannot read config file", file=sys.stderr)
        break
token = CONFIG.get('GITHUB_TOKEN')
if token:
    os.environ.setdefault('GITHUB_TOKEN', token)

# Flag for showing repositories with no matches and verbose logs (set by --show-all)
SHOW_ALL = False
# Flag for verbose logging (set by --verbose)
VERBOSE = False

# File extensions considered binary or non-text to skip scanning
SKIP_EXTENSIONS = {'.pdf', '.docx'}

# Counters for summary statistics
SKIP_FILETYPE_COUNT = 0
REGEX_FILTERED_COUNT = 0
# Count of repositories skipped due to cache
SKIP_CACHE_COUNT = 0
TIME_LIMIT = None
TIME_LIMIT_START = None

def is_text_file(path, blocksize=512):
    """
    Quick check to skip binary files: read a block and look for null bytes
    and ensure data appears text-like (low ratio of non-text bytes).
    """
    try:
        with open(path, 'rb') as f:
            chunk = f.read(blocksize)
    except Exception:
        return False
    # Null bytes are a strong indicator of binary files
    if b'\x00' in chunk:
        return False
    # Heuristic: if more than 30% of bytes are non-text, treat as binary
    nontext = sum(
        1 for b in chunk
        if (b < 32 and b not in (9, 10, 13)) or b > 126
    )
    if chunk and (nontext / len(chunk)) > 0.30:
        return False
    return True

def parse_args():
    parser = argparse.ArgumentParser(
        description='Clone git repositories, run YARA rules, and output results.')
    parser.add_argument(
        '--repos-file', '-r', type=str,
        help='Path to file containing repository URLs (one per line).')
    parser.add_argument(
        'repos', nargs='*',
        help='Repository URLs to clone.')
    parser.add_argument(
        '--rules-file', '-y',
        help='Path to YARA rules file.')
    parser.add_argument(
        '--rules-dir', '-Y', type=str,
        help='Path to directory containing YARA rule files (one per file).')
    parser.add_argument(
        '--number', '-n', type=int,
        help='Number of random repositories to fetch and scan.')
    parser.add_argument(
        '--days', type=int, default=1,
        help='Number of past days to include when fetching new repos.')
    parser.add_argument(
        '--per-page', type=int, default=100,
        help='Results per page to request from GitHub (max 100).')
    parser.add_argument(
        '--format', '-f', choices=['text', 'json', 'csv'],
        default='text', help='Output format.')
    parser.add_argument(
        '--output-file', '-o', type=str,
        help='Write output to file instead of stdout.')
    parser.add_argument(
        '--clone-dir', '-c', default='repos',
        help='Directory to clone repositories into.')
    parser.add_argument(
        '--cleanup', action='store_true',
        help='Remove cloned repositories after scanning.')
    # Removed --max-size: skip repositories by size is no longer supported
    parser.add_argument(
        '--time-per-repo', '-t', type=int, default=None,
        help='Maximum time to spend scanning each repository (in seconds).')
    parser.add_argument(
        '--show-all', action='store_true',
        help='Show all results including those with no matches.')
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output (show clone details and summary).')
    parser.add_argument(
        '--filter-rules', '-F', type=str,
        help='Comma-separated regex filters to apply to matched string data.')
    parser.add_argument(
        '--filter-file', type=str,
        help='Path to file containing regex filters separated by comma or newline.')
    parser.add_argument(
        '--watch-rules', '-w', type=str,
        help='Comma-separated YARA rule names to continuously watch; only list results matching these rules.')
    parser.add_argument(
        '--watch-until', type=int,
        help='Stop watching after matching given number of rule matches.')
    parser.add_argument(
        '--watch-interval', '-i', type=int, default=60,
        help='Interval in seconds between scans in watch mode.')
    parser.add_argument(
        '--list-rules', '-L', action='store_true',
        help='List YARA rule names from the provided rules file or directory and exit.')
    return parser.parse_args()

def load_repos_from_file(path):
    """Load repository URLs from a file, one per line."""
    repos = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            repos.append(line)
    return repos

def clone_repo(repo_url, base_dir):
    """Clone a git repository to the base directory."""
    name = os.path.splitext(os.path.basename(repo_url.rstrip('/')))[0]
    dest = os.path.join(base_dir, name)
    if os.path.isdir(dest):
        if VERBOSE:
            print(f'Info: Skip clone, directory exists: {dest}', file=sys.stderr)
    else:
        if VERBOSE:
            print(f'Cloning {repo_url} into {dest}...', file=sys.stderr)
        res = subprocess.run(
            ['git', 'clone', repo_url, dest],
            stdout=(None if VERBOSE else subprocess.DEVNULL),
            stderr=(None if VERBOSE else subprocess.DEVNULL),
        )
        if res.returncode != 0:
            print(f'Error: git clone failed for {repo_url}', file=sys.stderr)
            return None
    return dest

def parse_yara_output(output):
    records = []
    current = None
    for line in output.splitlines():
        if not line.strip():
            continue
        if not line.startswith('0x') and ':' in line and ' ' in line:
            parts = line.split(maxsplit=3)
            ns_rule, tags_raw, meta_raw, path = parts
            ns, rule = ns_rule.split(':', 1)
            tags = tags_raw.strip('[]')
            meta = meta_raw.strip('[]')
            current = {
                'namespace': ns,
                'rule': rule,
                'tags': tags.split(',') if tags else [],
                'meta': meta.split(',') if meta else [],
                'file': path,
                'strings': []
            }
            records.append(current)
        elif line.startswith('0x') and current is not None:
            parts = line.split(':', 2)
            if len(parts) == 3:
                offset, identifier, data = parts
                current['strings'].append({
                    'offset': offset,
                    'identifier': identifier,
                    'data': data.strip()
                })
    return records

def scan_repo(path, rules_file):
    """
    Scan a repository directory by walking through files, skipping
    binary or irrelevant files (e.g. in .git, pdf, docx), and
    running YARA rules against text-like files only.
    Respects a global time limit (TIME_LIMIT) set in watch mode.
    """
    global SKIP_FILETYPE_COUNT, TIME_LIMIT, TIME_LIMIT_START
    matches = []
    for root, dirs, files in os.walk(path):
        # Enforce time-per-repo limit if set
        if TIME_LIMIT is not None and TIME_LIMIT_START is not None and time.time() - TIME_LIMIT_START > TIME_LIMIT:
            if VERBOSE:
                print(f'Info: time-per-repo exceeded ({TIME_LIMIT}s) during scanning {path}', file=sys.stderr)
            return matches
        # Skip version control metadata directories entirely
        dirs[:] = [d for d in dirs if d != '.git']
        for fname in files:
            # Enforce time-per-repo limit inside file loop
            if TIME_LIMIT is not None and TIME_LIMIT_START is not None and time.time() - TIME_LIMIT_START > TIME_LIMIT:
                if VERBOSE:
                    print(f'Info: time-per-repo exceeded ({TIME_LIMIT}s) during scanning {path}', file=sys.stderr)
                return matches
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                SKIP_FILETYPE_COUNT += 1
                continue
            file_path = os.path.join(root, fname)
            if not is_text_file(file_path):
                SKIP_FILETYPE_COUNT += 1
                continue
            cmd = ['yara', '-s', '-m', '-g', '-e', rules_file, file_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0 and not result.stdout:
                if VERBOSE and result.stderr:
                    print(f'Warning: YARA scanning failed for {file_path}: {result.stderr}', file=sys.stderr)
                continue
            matches.extend(parse_yara_output(result.stdout))
    return matches

def parse_human_size(size_str):
    """Convert human-readable size (e.g. '10M', '1G') to bytes."""
    match = re.match(r'^(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>[kKmMgGtT](?:i?[bB])?)?$', size_str)
    if not match:
        raise ValueError(f"Invalid size value: {size_str}")
    num = float(match.group('num'))
    unit = match.group('unit') or ''
    unit = unit.lower().rstrip('b')
    multipliers = {'': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3, 't': 1024**4}
    if unit not in multipliers:
        raise ValueError(f"Unknown unit '{unit}' in size '{size_str}'")
    return int(num * multipliers[unit])

def get_remote_size(repo_url):
    """Return size in bytes of a remote GitHub repository via GitHub API."""
    match = re.match(
        r'(?:https?://github\\.com/|git@github\\.com:)(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\\.git)?$',
        repo_url)
    if not match:
        raise ValueError(f"Cannot determine remote size for non-GitHub URL: {repo_url}")
    owner = match.group('owner')
    repo = match.group('repo')
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = requests.get(api_url)
    resp.raise_for_status()
    data = resp.json()
    if 'size' not in data:
        raise ValueError(f"No size info in API response for {repo_url}")
    # GitHub 'size' field is in KB
    return data['size'] * 1024

def compile_filter_rules(rules_str=None, rules_file=None):
    """
    Compile regex patterns from a comma-separated string or from a file
    containing regexes separated by commas or new lines.
    """
    patterns = []
    if rules_str:
        patterns.extend([r.strip() for r in rules_str.split(',') if r.strip()])
    if rules_file:
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f'Error: cannot read filter file {rules_file}: {e}', file=sys.stderr)
            sys.exit(1)
        patterns.extend([r.strip() for r in re.split(r'[,\\n]', content) if r.strip()])
    try:
        return [re.compile(p) for p in patterns]
    except re.error as e:
        print(f'Error: invalid regex filter: {e}', file=sys.stderr)
        sys.exit(1)

def filter_matches(records, regex_list):
    """
    Filter match records by removing string matches whose data matches
    any of the provided regex patterns. Updates global REGEX_FILTERED_COUNT.
    """
    global REGEX_FILTERED_COUNT
    filtered = []
    for rec in records:
        new_strings = []
        for s in rec['strings']:
            if any(regex.search(s['data']) for regex in regex_list):
                REGEX_FILTERED_COUNT += 1
            else:
                new_strings.append(s)
        if new_strings:
            rec['strings'] = new_strings
            filtered.append(rec)
    return filtered

def list_rules(rule_paths):
    """
    Parse YARA rule files and print the names of all rules.
    """
    names = set()
    pattern = re.compile(r'^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)')
    for path in rule_paths:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    m = pattern.match(line)
                    if m:
                        names.add(m.group(1))
        except Exception as e:
            print(f'Error reading rule file {path}: {e}', file=sys.stderr)
    for name in sorted(names):
        print(name)
    return names

def watch_mode(args, rule_paths, filter_patterns):
    """
    Continuously fetch new GitHub repositories and scan for specific rule matches.
    Stops when --watch-until count is reached (if specified).
    """
    cache_file = 'repo_cache.txt'
    cache = set()
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    cache.add(line)
    # Determine which rules to watch and log if verbose
    if args.watch_rules:
        rule_names = [r.strip() for r in args.watch_rules.split(',') if r.strip()]
        if VERBOSE:
            print(f'Entering watch mode for rules: {", ".join(rule_names)}', file=sys.stderr)
    else:
        rule_names = None
        if VERBOSE:
            print('Entering watch mode for all rules', file=sys.stderr)
    total_matches = 0
    scanned_count = 0
    since_date = (datetime.datetime.utcnow() - datetime.timedelta(days=args.days)).date().isoformat()
    while True:
        try:
            fetched = get_new_repos(since_date, per_page=args.per_page)
        except Exception as e:
            print(f'Error fetching new repos: {e}', file=sys.stderr)
            time.sleep(args.watch_interval)
            continue
        new_urls = [r['html_url'] for r in fetched if r.get('html_url') and r['html_url'] not in cache]
        if not new_urls:
            time.sleep(args.watch_interval)
            continue
        repo_url = new_urls[0]
        scanned_count += 1
        # For verbose mode, log each repository processed
        if VERBOSE:
            print(f"[Scanned {scanned_count}] Processing repository: {repo_url} (matches so far: {total_matches})", file=sys.stderr)
        cloned = clone_repo(repo_url, args.clone_dir)
        if not cloned:
            cache.add(repo_url)
            with open(cache_file, 'a', encoding='utf-8') as f:
                f.write(repo_url + '\n')
            time.sleep(args.watch_interval)
            continue
        # Initialize global time limit for repository scanning
        global TIME_LIMIT, TIME_LIMIT_START
        if args.time_per_repo:
            TIME_LIMIT = args.time_per_repo
            TIME_LIMIT_START = time.time()
        else:
            TIME_LIMIT = None
            TIME_LIMIT_START = None
        matches_all = []
        for rp in rule_paths:
            matches_all.extend(scan_repo(cloned, rp))
        if filter_patterns:
            matches_all = filter_matches(matches_all, filter_patterns)
        if rule_names is not None:
            matches_by_rule = [rec for rec in matches_all if rec['rule'] in rule_names]
        else:
            matches_by_rule = matches_all
        if matches_by_rule:
            print(f'\n[Match] Repository: {repo_url}', file=sys.stderr)
            for rec in matches_by_rule:
                for s in rec['strings']:
                    print(f"  - {rec['rule']} in {rec['file']} at {s['offset']}: {s['identifier']} => {s['data']}", file=sys.stderr)
            count = sum(len(rec['strings']) for rec in matches_by_rule)
            total_matches += count
            print(f'[Total matches so far: {total_matches}]', file=sys.stderr)
        if args.cleanup:
            shutil.rmtree(cloned, ignore_errors=True)
        cache.add(repo_url)
        with open(cache_file, 'a', encoding='utf-8') as f:
            f.write(repo_url + '\n')
        # After scanning, update a single-line progress for non-verbose mode
        if not VERBOSE:
            msg = f"[Scanned {scanned_count}] {repo_url} (matches so far: {total_matches})"
            sys.stderr.write(f"\r{msg}")
            sys.stderr.flush()
        # Check watch-until termination
        if args.watch_until and total_matches >= args.watch_until:
            if VERBOSE:
                print(f'Watch target reached: {total_matches} matches (>= {args.watch_until})', file=sys.stderr)
            else:
                # finish the progress line
                sys.stderr.write("\n")
            return
        # Wait before next scan
        if VERBOSE:
            print(f'Waiting {args.watch_interval}s before next scan...', file=sys.stderr)
        time.sleep(args.watch_interval)

def output_text(results, writer):
    for item in results:
        writer.write(f"Repository: {item['url']}\n")
        writer.write(f"Path: {item['path']}\n")
        matches = item['matches']
        if not matches:
            writer.write('No matches found.\n\n')
            continue
        total = sum(len(rec['strings']) for rec in matches)
        writer.write(f'Found {total} matches:\n')
        for rec in matches:
            for s in rec['strings']:
                writer.write(
                    f"  - {rec['rule']} ({rec['namespace']}) in {rec['file']} "
                    f"at {s['offset']}: {s['identifier']} => {s['data']}\n"
                )
        writer.write('\n')

def output_json(results, writer):
    json.dump(results, writer, indent=2)

def output_csv(results, writer):
    csv_writer = csv.writer(writer)
    header = ['url', 'path', 'namespace', 'rule', 'tags', 'meta', 'file', 'offset', 'identifier', 'data']
    csv_writer.writerow(header)
    for item in results:
        for rec in item['matches']:
            tags = ';'.join(rec['tags'])
            meta = ';'.join(rec['meta'])
            for s in rec['strings']:
                csv_writer.writerow([
                    item['url'], item['path'], rec['namespace'], rec['rule'],
                    tags, meta, rec['file'], s['offset'], s['identifier'], s['data']
                ])

def main():
    args = parse_args()
    # Handle listing of YARA rule names
    if args.list_rules:
        # Validate rule file/dir arguments
        if args.rules_dir and args.rules_file:
            print('Error: specify either --rules-file or --rules-dir, not both', file=sys.stderr)
            sys.exit(1)
        if not args.rules_file and not args.rules_dir:
            print('Error: must specify a YARA rule file or rules directory', file=sys.stderr)
            sys.exit(1)
        # Collect rule paths
        paths = []
        if args.rules_dir:
            if not os.path.isdir(args.rules_dir):
                print(f'Error: rules directory not found: {args.rules_dir}', file=sys.stderr)
                sys.exit(1)
            for fname in sorted(os.listdir(args.rules_dir)):
                path = os.path.join(args.rules_dir, fname)
                if os.path.isfile(path):
                    paths.append(path)
        else:
            paths = [args.rules_file]
        list_rules(paths)
        return
    # Configure verbosity and show-all flags
    global SHOW_ALL, VERBOSE, SKIP_CACHE_COUNT
    SHOW_ALL = args.show_all
    VERBOSE = args.verbose
    # Compile regex filters if provided
    if args.filter_rules and args.filter_file:
        print('Error: specify either --filter-rules or --filter-file, not both', file=sys.stderr)
        sys.exit(1)
    if args.filter_rules or args.filter_file:
        filter_patterns = compile_filter_rules(args.filter_rules, args.filter_file)
    else:
        filter_patterns = []
    # Handle watch mode before selecting repos
    if args.watch_rules or args.watch_until:
        # Validate rule file/dir arguments
        if args.rules_dir and args.rules_file:
            print('Error: specify either --rules-file or --rules-dir, not both', file=sys.stderr)
            sys.exit(1)
        if not args.rules_file and not args.rules_dir:
            print('Error: must specify a YARA rule file or rules directory', file=sys.stderr)
            sys.exit(1)
        # Collect rule paths
        rule_paths = []
        if args.rules_dir:
            if not os.path.isdir(args.rules_dir):
                print(f'Error: rules directory not found: {args.rules_dir}', file=sys.stderr)
                sys.exit(1)
            for fname in sorted(os.listdir(args.rules_dir)):
                path = os.path.join(args.rules_dir, fname)
                if os.path.isfile(path):
                    rule_paths.append(path)
        else:
            rule_paths = [args.rules_file]
        watch_mode(args, rule_paths, filter_patterns)
        return
    if args.number is not None:
        if args.repos or args.repos_file:
            print('Error: specify either --number or repo URLs/--repos-file, not both', file=sys.stderr)
            sys.exit(1)
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=args.days)).date().isoformat()
        fetched = get_new_repos(since, per_page=args.per_page)
        if not fetched:
            print('No repositories found.', file=sys.stderr)
            sys.exit(0)
        count = min(args.number, len(fetched))
        selected = random.sample(fetched, count)
        repos = [repo['html_url'] for repo in selected]
    else:
        if not args.repos and not args.repos_file:
            print('Error: must specify at least one repo URL, --repos-file, or --number', file=sys.stderr)
            sys.exit(1)
        if args.repos and args.repos_file:
            print('Error: specify either repos URLs or --repos-file, not both', file=sys.stderr)
            sys.exit(1)
        repos = args.repos or load_repos_from_file(args.repos_file)
    if args.rules_dir and args.rules_file:
        print('Error: specify either --rules-file or --rules-dir, not both', file=sys.stderr)
        sys.exit(1)
    if not args.rules_file and not args.rules_dir:
        print('Error: must specify a YARA rule file or rules directory', file=sys.stderr)
        sys.exit(1)
    rule_paths = []
    if args.rules_dir:
        if not os.path.isdir(args.rules_dir):
            print(f'Error: rules directory not found: {args.rules_dir}', file=sys.stderr)
            sys.exit(1)
        for fname in sorted(os.listdir(args.rules_dir)):
            path = os.path.join(args.rules_dir, fname)
            if os.path.isfile(path):
                rule_paths.append(path)
    else:
        rule_paths = [args.rules_file]

    os.makedirs(args.clone_dir, exist_ok=True)
    # Read and apply repository cache to skip already processed repos
    cache_file = 'repo_cache.txt'
    cache = set()
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    cache.add(line)
    new_repos = []
    for repo in repos:
        if repo in cache:
            SKIP_CACHE_COUNT += 1
        else:
            new_repos.append(repo)
    repos = new_repos
    # Removed --max-size functionality
    results = []
    # Iterate repositories with progress bar
    for repo in tqdm(repos, desc='Processing repos', unit='repo'):
        cloned = clone_repo(repo, args.clone_dir)
        if not cloned:
            continue
        matches = []
        for rp in rule_paths:
            matches.extend(scan_repo(cloned, rp))
        # Apply regex-based filtering to matches
        if filter_patterns:
            matches = filter_matches(matches, filter_patterns)
        results.append({'url': repo, 'path': cloned, 'matches': matches})
        if args.cleanup:
            shutil.rmtree(cloned, ignore_errors=True)

    if not args.show_all:
        results = [item for item in results if item['matches']]

    if args.output_file:
        out_fh = open(args.output_file, 'w', encoding='utf-8')
    else:
        out_fh = sys.stdout
    if args.format == 'text':
        output_text(results, out_fh)
    elif args.format == 'json':
        output_json(results, out_fh)
    else:
        output_csv(results, out_fh)
    if args.output_file:
        out_fh.close()

    # Update repository cache with newly processed repos
    if repos:
        with open(cache_file, 'a', encoding='utf-8') as f:
            for repo in repos:
                f.write(repo + '\n')

    # Print summary of matches and filtering
    match_counts = {}
    for item in results:
        for rec in item['matches']:
            match_counts[rec['rule']] = match_counts.get(rec['rule'], 0) + len(rec['strings'])
    total_matches = sum(match_counts.values())
    if VERBOSE:
        print('\nSummary:', file=sys.stderr)
        print(f'Repos skipped due to cache: {SKIP_CACHE_COUNT}', file=sys.stderr)
        print(f'Matches skipped due to filetype: {SKIP_FILETYPE_COUNT}', file=sys.stderr)
        if filter_patterns:
            print(f'Matches filtered by regex rules: {REGEX_FILTERED_COUNT}', file=sys.stderr)
        print(f'Total matches (after filtering): {total_matches}', file=sys.stderr)
        print('Matches by rule:', file=sys.stderr)
        for rule, count in sorted(match_counts.items()):
            print(f'  {rule}: {count}', file=sys.stderr)

if __name__ == '__main__':
    main()
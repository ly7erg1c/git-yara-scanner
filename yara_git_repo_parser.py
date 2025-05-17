#!/usr/bin/env python3
"""Command-line tool to clone git repositories, scan them with YARA rules, and output results."""

import argparse
import subprocess
import os
import sys
import shutil
import json
import csv

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
        '--rules-file', '-y', required=True,
        help='Path to YARA rules file.')
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
        print(f'Info: Skip clone, directory exists: {dest}', file=sys.stderr)
    else:
        print(f'Cloning {repo_url} into {dest}...', file=sys.stderr)
        res = subprocess.run(['git', 'clone', repo_url, dest])
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
    cmd = ['yara', '-r', '-s', '-m', '-g', '-e', rules_file, path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 and not result.stdout:
        if result.stderr:
            print(f'Error: YARA scanning failed: {result.stderr}', file=sys.stderr)
        return []
    return parse_yara_output(result.stdout)

def main():
    args = parse_args()
    if not args.repos and not args.repos_file:
        print('Error: must specify at least one repo URL or --repos-file', file=sys.stderr)
        sys.exit(1)
    if args.repos and args.repos_file:
        print('Error: specify either repos URLs or --repos-file, not both', file=sys.stderr)
        sys.exit(1)
    repos = args.repos or load_repos_from_file(args.repos_file)
    os.makedirs(args.clone_dir, exist_ok=True)
    for repo in repos:
        cloned = clone_repo(repo, args.clone_dir)
        if args.cleanup and cloned:
            shutil.rmtree(cloned, ignore_errors=True)

if __name__ == '__main__':
    main()
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
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--repos-file', '-r', type=str,
        help='Path to file containing repository URLs (one per line).')
    group.add_argument(
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

def main():
    args = parse_args()
    repos = args.repos or load_repos_from_file(args.repos_file)
    os.makedirs(args.clone_dir, exist_ok=True)
    for repo in repos:
        cloned = clone_repo(repo, args.clone_dir)
        if args.cleanup and cloned:
            shutil.rmtree(cloned, ignore_errors=True)

if __name__ == '__main__':
    main()
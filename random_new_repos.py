#!/usr/bin/env python3
"""
Fetch a number of random new GitHub repositories created within a given time frame.
"""

import os
import sys
import argparse
try:
    import requests
except ImportError:
    requests = None
import random
import datetime


def get_new_repos(since_date, per_page=100):
    """
    Query the GitHub API for repositories created since the given date.

    Returns a list of repository items (dicts) from the search response.
    """
    token = os.environ.get('GITHUB_TOKEN')
    headers = {}
    if token:
        headers['Authorization'] = f"token {token}"
    params = {
        'q': f'created:>={since_date}',
        'sort': 'created',
        'order': 'desc',
        'per_page': per_page,
    }
    response = requests.get('https://api.github.com/search/repositories', headers=headers, params=params)
    if response.status_code != 200:
        print(f"Error: GitHub API returned status {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)
    data = response.json()
    return data.get('items', [])


def main():
    parser = argparse.ArgumentParser(
        description='Get random new GitHub repositories.'
    )
    parser.add_argument('-n', '--number', type=int, default=5,
                        help='Number of random repositories to return.')
    parser.add_argument('--days', type=int, default=1,
                        help='How many past days to include when fetching new repos.')
    parser.add_argument('--per_page', type=int, default=100,
                        help='Results per page to request from GitHub (max 100).')
    args = parser.parse_args()

    # Calculate date threshold for filtering new repositories
    since = (datetime.datetime.utcnow() - datetime.timedelta(days=args.days)).date().isoformat()

    # Fetch new repositories from GitHub
    repos = get_new_repos(since, per_page=args.per_page)
    if not repos:
        print('No repositories found.', file=sys.stderr)
        sys.exit(0)

    # Sample random repositories from the fetched list
    count = min(args.number, len(repos))
    selected = random.sample(repos, count)

    # Print selected repository URLs
    for repo in selected:
        print(repo['html_url'])


if __name__ == '__main__':
    main()
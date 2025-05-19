# YARA Git Scanner

A command-line tool to clone one or more Git repositories, scan them with YARA rules,
and output the results in various formats.

This tool automatically skips version control metadata directories (e.g., .git) and
non-text files (e.g., PDF, DOCX) by performing a quick text check before running YARA
rules against each file.

## Installation

Before using the scripts, create and activate a Python virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configuration File

Optionally, create a YAML configuration file named `config.yaml` (or `config.yml`) in the project root to set your GitHub personal access token:

```yaml
GITHUB_TOKEN: your_personal_access_token
```

If provided, the script will automatically load this file and set the `GITHUB_TOKEN` environment variable, so you don't need to export it manually.

## Usage

```bash
./yara_git_repo_parser.py [--repos-file FILE | <repo1> [<repo2> ...] | --number N] \\
    [--days DAYS] [--per-page PER_PAGE] \\
    [--rules-file RULES_YAR | --rules-dir RULES_DIR] \\
    [--format {text,json,csv}] \\
    [--output-file FILE] \\
    [--clone-dir DIR] \\
    [--time-per-repo SECONDS] \\
    [--cleanup] [--show-all] [--verbose] [--filter-rules REGEX[,REGEX...]] [--filter-file FILE]
```

By default, the script shows a progress bar indicating how many repositories have been cloned and scanned, and hides detailed cloning output and the summary. To enable detailed logs and the end-of-run summary (including cache skips and match filtering counts), add the `--verbose` flag.

This tool maintains a cache file (`repo_cache.txt`) of previously scanned repositories. Repositories in this cache are skipped automatically (counted in the summary as "repos skipped due to cache"), and newly processed repos are appended to the cache for future runs.

Optional filters for excluding string matches:

```bash
  --filter-rules <regex1,regex2,...>   Filters out matches whose data matches any of the provided regex patterns.
  --filter-file <file>                Read filters from file (comma- or newline-separated regex patterns).
```

Detailed summary (cache skips, filetype skips, regex-filtered counts, and total match counts) is printed to stderr at the end of the run when `--verbose` is enabled.

Note: the `--time-per-repo` option limits how long the scanner will spend scanning each repository. To avoid API rate limits when cloning GitHub repositories, set the `GITHUB_TOKEN` environment variable for authenticated requests.

### Examples

Scan a single repository:

```bash
./yara_git_repo_parser.py https://github.com/user/repo.git --rules-file rules.yar
```


Scan multiple repositories listed in a file (output JSON):

```bash
./yara_git_repo_parser.py --repos-file repos.txt --rules-file rules.yar --format json
```

Filter out string matches matching regex patterns (e.g., 'password' or 'secret'):

```bash
./yara_git_repo_parser.py --repos-file repos.txt --rules-file rules.yar \
    --filter-rules password,secret
```

Remove cloned repositories after scanning:

```bash
./yara_git_repo_parser.py https://github.com/user/repo.git --rules-file rules.yar --cleanup
```

Limit scanning time per repository to 60 seconds and write output to a file:

```bash
./yara_git_repo_parser.py https://github.com/user/repo.git \
    --rules-file rules.yar --time-per-repo 60 --output-file results.txt
```

### Combined Usage

Scan random new repositories and scan with rules directory:

```bash
./yara_git_repo_parser.py --number 5 --rules-dir yara_rules
```

Include repositories with no matches (`--show-all`) and verbose logs (`--verbose`):

```bash
./yara_git_repo_parser.py --number 10 --rules-dir yara_rules --show-all --verbose
```

### Watch Mode

Continuously scan new repositories for matches of specific YARA rules.

Options:

- `--watch-rules RULE1,RULE2,...`: Comma-separated list of rule names to watch.
- `--watch-until N`: Stop after matching total N rule instances.
- `--watch-interval SECONDS`: Interval in seconds between scan cycles (default 60).

Examples:

```bash
# Watch for any matches of the 'SecretKey' rule every 5 minutes
./yara_git_repo_parser.py --rules-dir yara_rules --watch-rules SecretKey --watch-interval 300

# Watch for matches of 'SecretKey' or 'Password' and stop after 20 matches
./yara_git_repo_parser.py --rules-dir yara_rules --watch-rules SecretKey,Password --watch-until 20
```

### Listing Available Rules

List the names of all YARA rules in a rules file or directory:

```bash
./yara_git_repo_parser.py --rules-dir yara_rules --list-rules
```

## Random New Repositories Script

The `random_new_repos.py` script fetches recently created repositories on GitHub and outputs a random selection of repository URLs. Note that this functionality is also integrated into `yara_git_repo_parser.py` via the `--number`, `--days`, and `--per-page` options.

### Prerequisites

- A GitHub personal access token set in the `GITHUB_TOKEN` environment variable (recommended to avoid rate limits).

### Usage

```bash
# Activate your Python virtual environment
source .venv/bin/activate

# Get 5 random new repositories created in the last day (default)
./random_new_repos.py --number 5

# Get 10 random new repositories created in the last 3 days
./random_new_repos.py --number 10 --days 3
```

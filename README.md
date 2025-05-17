# YARA Git Repo Parser

A command-line tool to clone one or more Git repositories, scan them with YARA rules,
and output the results in various formats.

## Usage

```bash
./yara_git_repo_parser.py [--repos-file FILE | <repo1> [<repo2> ...]] \
    --rules-file RULES_YAR \
    [--format {text,json,csv}] \
    [--output-file FILE] \
    [--clone-dir DIR] \
    [--cleanup]
```

### Examples

Scan a single repository:

```bash
./yara_git_repo_parser.py https://github.com/user/repo.git --rules-file rules.yar
```

Scan multiple repositories listed in a file (output JSON):

```bash
./yara_git_repo_parser.py --repos-file repos.txt --rules-file rules.yar --format json
```

Remove cloned repositories after scanning:

```bash
./yara_git_repo_parser.py https://github.com/user/repo.git --rules-file rules.yar --cleanup
```
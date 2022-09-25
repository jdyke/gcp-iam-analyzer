# GCP IAM Analyzer

This tool is an all-in-one GCP IAM analyzer with helpful functions for working with roles and permissions.

## Table of Contents

- [Features](#features)
  - [Role Analysis](#role-analysis)
  - [Permissions Analysis](#permissions-analysis)
- [Usage](#usage)
- [Example](#example)
- [Feedback](#feedback)

## Features

There are two main types of features this tool offers: role analysis and permissions analysis. 

### Role Analysis

Currently supports up to 2 IAM roles to:

- Calculate the differences in permissions between the two. (`-d` flag)
- Which permissions the two roles share. (`-s` flag)
- Lists permissions for a given role or list of roles. (supports 1 + N roles). (`-l` flag)
- Or can do all of the above at once. (`-a` flag)

In order to determine what permissions a role has we need some type of role -> permission lookup. We have a roles database via a different project [gcp_iam_update_bot](https://github.com/jdyke/gcp_iam_update_bot) which keeps an up to date list of all GCP IAM roles and their permissions (refreshes every 12 hours).

Before any role analysis takes place the script will look for the `roles/` directory and prompt you to download it if it does not exist:

```bash
./gcp-iam-analyzer.py -d vpcaccess.admin vpcaccess.viewer
ERROR:"roles" folder does not exist. This is required for analysis.
Do you want to download the "roles" folder now? y/n
```

You update your local roles database at anytime via `./gcp-iam-analyzer.py -r`.

### Permissions Analysis

- Can calculate which IAM roles have a specific IAM permission. (`-p` flag)

## Usage

```bash
./gcp-iam-analyzer.py --help
usage: gcp-iam-analyzer.py [-h] [-d ROLES [ROLES ...]] [-s ROLES [ROLES ...]] [-a ROLES [ROLES ...]]
                           [-l ROLES [ROLES ...]] [-p PERM [PERM ...]] [-r]

Compares GCP IAM roles and outputs analysis.

optional arguments:
  -h, --help            show this help message and exit
  -d ROLES [ROLES ...], --diff ROLES [ROLES ...]
                        Compares roles and outputs the permissions difference.
  -s ROLES [ROLES ...], --shared ROLES [ROLES ...]
                        Compares roles and outputs the shared permissions.
  -a ROLES [ROLES ...], --all ROLES [ROLES ...]
                        Compares roles and outputs the differences and the shared permissins.
  -l ROLES [ROLES ...], --list ROLES [ROLES ...]
                        Lists permissions for role(s).
  -p PERM [PERM ...], --perm PERM [PERM ...]
                        Lists roles which contain a specific permission.
  -r, --refresh         Refreshes the local "roles" folder
```

## Example

Let's say we have a user in GCP that has the `vpcaccess.admin` role and you want to find out how many permissions they would "lose" if they were assigned the `vpcaccess.viewer` role.

```bash
./gcp-iam-analyzer.py -d vpcaccess.viewer vpcaccess.admin

Role "vpcaccess.viewer" differences:
'N/A'
Role "vpcaccess.admin" differences:
'vpcaccess.connectors.delete'
'vpcaccess.connectors.create'
'vpcaccess.connectors.use'
```

The above output shows that by assigning the `vpcaccess.viewer` role and removing the `vpcaccess.admin` role the user would lose:

```bash
'vpcaccess.connectors.create',
'vpcaccess.connectors.delete',
'vpcaccess.connectors.use'
 ```

## Feedback

Feel free to open an issue if you encounter a bug or reach out via twitter [@jasonadyke](https://twitter.com/jasonadyke)

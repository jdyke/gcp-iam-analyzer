# gcp-iam-analyzer
I wrote this to help in my day to day working in GCP. A lot of the time I am doing role comparisons to see which role has more permissions, what the differences are, etc.

## Features
Compares and analyzes GCP IAM roles. Currently supports 2 role comparisons to find:
- The differences between the two. 
- Which permissions the two roles share.
- Or both! Can output differences and shared permissions in the same flow.

In order to determine what permissions a role has we need some type of role -> permission lookup. Luckily, I already have that via a different project [gcp_iam_update_bot](https://github.com/jdyke/gcp_iam_update_bot) which keeps an up to date list of ALL GCP IAM roles and their permissions (refreshes every 12 hours.

Before any role anlalysis takes place the script will look for the `roles/` directory and prompt you to download it if it does not exist:
```sh
./gcp-iam-analyzer.py -d vpcaccess.admin vpcaccess.viewer
ERROR:"roles" folder does not exist. This is required for analysis.
Do you want to download the "roles" folder now? y/n
```

Otherwise you can always re-update your local roles database via `./gcp-iam-analyzer.py -r`.

## Execution:

```sh
./gcp-iam-analyzer.py --help
usage: gcp-iam-analyzer.py [-h] [-d ROLES [ROLES ...]] [-s ROLES [ROLES ...]] [-a ROLES [ROLES ...]] [-r]

Compares GCP IAM roles and outputs analysis.

optional arguments:
  -h, --help            show this help message and exit
  -d ROLES [ROLES ...], --diff ROLES [ROLES ...]
                        Compares roles and outputs the permissions difference.
  -s ROLES [ROLES ...], --shared ROLES [ROLES ...]
                        Compares roles and outputs the shared permissions.
  -a ROLES [ROLES ...], --all ROLES [ROLES ...]
                        Compares roles and outputs the differences and the shared permissinos.
  -r, --refresh         Refreshes the local "roles" folder.
```


## Example 
Let's say we have a user in GCP that has the `vpcaccess.admin` role and you want to find out how many permissions they would "lose" if they were assigned the `vpcaccess.viewer` role. 

```sh
./gcp-iam-analyzer.py -d vpcaccess.viewer vpcaccess.admin

Role "vpcaccess.viewer" differences:
'N/A'
Role "vpcaccess.admin" differences:
'vpcaccess.connectors.delete'
'vpcaccess.connectors.create'
'vpcaccess.connectors.use'
```

The above output shows that by assigning the `vpcaccess.viewer` role and removing the `vpcaccess.admin` role the user would lose:
```sh
'vpcaccess.connectors.create',
'vpcaccess.connectors.delete',
'vpcaccess.connectors.use'
 ```

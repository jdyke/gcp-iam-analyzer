# gcp-iam-analyzer
I wrote this to help in my day to day working in GCP. A lot of the time I am doing role comparisons to see which role has more permissions, what the differences are, etc.

## Features
Compares and analyzes GCP IAM roles. Currently supports 2 role comparisons to find:
- The differences between the two. 
- Which permissions the two roles share.
- Or both! Can output differences and shared permissions in the same flow.


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
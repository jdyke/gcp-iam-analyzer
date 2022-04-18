#!/usr/bin/python3

import argparse
import logging
import os
import requests
import tarfile
import sys
import shutil
import json
from pprint import pprint


def inputs(args):
    if args["diff"]:
        if len(args["diff"]) != 2:
            logging.error("Need 2 roles to compare differences..")
            logging.error("Please rerun with 2 roles. Exiting. \n")
            sys.exit(1)
        else:
            logging.info("Diff flag set, will output permissions diff. \n")
            diff_roles = args["diff"]
            perms_diff(diff_roles)
    if args["shared"]:
        if len(args["shared"]) != 2:
            logging.error("Need 2 roles to compare shared permissions..")
            logging.error("Please rerun with 2 roles. Exiting. \n")
            sys.exit(1)
        else:
            logging.info("Shared flag set, will output shared permissions. \n")
            shared_roles = args["shared"]
            perms_shared(shared_roles)
    if args["all"]:
        if len(args["all"]) != 2:
            logging.error(
                "Need 2 roles to compare both different and shared permissions..")
            logging.error("Please rerun with 2 roles. Exiting. \n")
            sys.exit(1)
        else:
            logging.info(
                "All flag set, will output diff and shared permissions. \n")
            all_roles = args["all"]
            perms_all(all_roles)
    if args["list"]:
        logging.info(
            "List flag set, will output permissions for supplied role(s). \n")
        list_roles = args["list"]
        list_perms(list_roles)


def perms_diff(diff_roles):
    """
    Takes 2 roles and displays the different permissions contained in each.
    """

    # Currently only supports comparing 2 roles
    # Can safely assume only 2 elements in list
    role_one = diff_roles[0]
    role_two = diff_roles[1]

    # Generate the list of permissions per role
    role_one_perms = get_permissions(role_one)
    role_two_perms = get_permissions(role_two)

    # Get the diff for role1
    role_one_diff = set(role_one_perms).difference(set(role_two_perms))
    print(f"# Role \"{role_one}\" differences:")
    if not role_one_diff:
        role_one_diff = "N/A"
        pprint(role_one_diff)
    else:
        for permission in role_one_diff:
            pprint(permission)

    # Get the diff for role2
    role_two_diff = set(role_two_perms).difference(set(role_one_perms))

    print(f"# Role \"{role_two}\" differences:")
    if not role_two_diff:
        role_two_diff = "N/A"
        pprint(role_two_diff)
    else:
        for permission in role_two_diff:
            pprint(permission)


def get_permissions(role_name):
    """
    Takes a role and finds the permissions it contains
    """
    # Create a list of permissions for a given role
    with open(f"./roles/{role_name}", "r") as role_file:
        role_file = json.load(role_file)
        role_perms = role_file["includedPermissions"]

    return role_perms


def perms_shared(shared_roles):
    """
    Takes 2 roles and displays the shared permissions contained in each.
    """

    # Currently only supports comparing 2 roles
    # Can safely assume only 2 elements in list
    role_one = shared_roles[0]
    role_two = shared_roles[1]

    # Generate the list of permissions per role
    role_one_perms = get_permissions(role_one)
    role_two_perms = get_permissions(role_two)

    # Compare the two lists and display similarities
    shared_perms = set(role_one_perms) & set(role_two_perms)
    print(
        f"# The shared permissions between {role_one} and {role_two} are: \n")
    pprint(shared_perms)


def perms_all(all_roles):
    """
    Compares 2 roles and outputs the differences and the shared permissinos.
    """
    logging.info("Finding differences.. \n")
    perms_diff(all_roles)

    logging.info("\n Finding shared permissions.. \n")
    perms_shared(all_roles)


def roles_refresh():
    """
    This function:
        - Downloads the most recent GCP IAM roles dataset
        - Extracts only the roles data
        - Cleans up old unneeded files/directories
    """

    try:
        # Get the latest release tag URL
        logging.info("Downloading latest GCP IAM roles dataset... \n")
        response = requests.get(
            "https://api.github.com/repos/jdyke/gcp_iam_update_bot/releases/latest")

        # Construct the tarball download URL
        tarball_name = response.json()["tag_name"]
        download_url = f"https://github.com/jdyke/gcp_iam_update_bot/archive/refs/tags/{tarball_name}.tar.gz"

        # Download location
        target_path = "latest.tar.gz"

        # Download tarball
        response = requests.get(download_url, stream=True)
        if response.status_code == 200:
            with open(target_path, 'wb') as f:
                f.write(response.raw.read())
    except:
        logging.error("Could not download roles dataset")
        raise

    # Extract only "roles/" folder
    logging.info("Extracting roles from dataset... \n")
    with tarfile.open(target_path) as tar:
        tar.extractall(members=members(tar))

    logging.info("Formatting data and cleaning up unneeded files... \n")
    # Move tarball directory to "roles/"
    move_dir = "gcp_iam_update_bot-" + tarball_name
    move_directory(move_dir)


def list_perms(list_roles):
    """
    Lists permissions for each supplied role.

    Args:
        list_roles (list): A list of roles
    """

    # For each role in the list
    # Find the permissions
    for role in list_roles:
        perms_list = get_permissions(role)
        print(f"# The permissions for {role} are:")
        pprint(perms_list)


def move_directory(move_dir):
    """
    Moves the tarball directory to "roles/"
    """
    # Check if directory already exists
    # If so, delete. We are refreshing the data.
    roles_dir = os.path.isdir("roles/")
    if roles_dir:
        shutil.rmtree("roles/")

    # Move directory
    directory_to_move = move_dir + "/roles/"
    try:
        shutil.move(directory_to_move, "./roles/")
    except:
        "Could not rename tarball directory"
        raise

    # Clean tarball and empty dir
    cleanup(move_dir)


def cleanup(move_dir):
    """
    Removes empty or unneeded directories
    """
    try:
        os.remove("latest.tar.gz")
    except:
        logging.error("Could not remove tarball.")

    try:
        os.rmdir(move_dir)
    except:
        logging.error("Could not remove empty tarball directory.")


def members(tarball):
    """
    Returns/yields only files in the "roles/" directory

    "member" is a term tarfile uses for files inside a tarball
    """
    l = len("roles/")
    for member in tarball.getmembers():
        if "roles/" in member.path:
            yield member


if __name__ == "__main__":
    # Configure logging format
    # TODO: Update to info logging
    logging.basicConfig(format='%(levelname)s:%(message)s',
                        level=logging.ERROR)

    # Configure arguments
    parser = argparse.ArgumentParser(
        description="Compares GCP IAM roles and outputs analysis.")
    parser.add_argument("-d", "--diff", nargs='+', metavar="ROLES",
                        help="Compares roles and outputs the permissions difference.")
    parser.add_argument("-s", "--shared", nargs='+', metavar="ROLES",
                        help="Compares roles and outputs the shared permissions.")
    parser.add_argument("-a", "--all", nargs='+', metavar="ROLES",
                        help="Compares roles and outputs the differences and the shared permissins.")
    parser.add_argument("-l", "--list", nargs='+',
                        metavar="ROLES", help="Lists permissions for role(s).")
    parser.add_argument(
        "-r", "--refresh", help="Refreshes the local \"roles\" folder.", action='store_true')

    args = vars(parser.parse_args())

    # Check if user wants to download or refresh roles folder.
    if args["refresh"]:
        logging.info(
            "Refresh flag set, will refresh local \"roles\" folder and continue..")
        roles_refresh()

    # Require at least one argument
    if not args["diff"] and not args["shared"] and not args["all"] and not args["list"]:
        logging.error("One argument must be supplied.")
        sys.exit(0)

    # check if roles folder exists
    path = "./roles"
    is_folder = os.path.isdir(path)

    if is_folder:
        logging.debug("Roles folder exists.. proceeding")
    else:
        logging.error(
            "\"roles\" folder does not exist. This is required for analysis.")

        # Ask user if they want to dl roles folder
        refresh = input(
            "Do you want to download the \"roles\" folder now? y/n \n")
        if refresh == "y":
            roles_refresh()
        elif refresh == "n":
            logging.info(
                "\"roles\" folder is required for analysis. Please execute with -r flag.")
        else:
            logging.error(
                f"Invalid or no input found. Value entered: \"{refresh}\"")

    inputs(args)

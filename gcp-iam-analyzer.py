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
import re


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
    if args["perm"]:
        logging.info(
            "Permission flag set, will output all roles which contain the supplied permission(s). \n")
        if len(args["perm"]) == 1:
            role_permission = str(args["perm"][0])
            list_roles_for_perm(role_permission)
        else:
            for permission in args["perm"]:
                list_roles_for_perm(permission)


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
    print(f"\n # Role \"{role_one}\" differences:")
    if not role_one_diff:
        role_one_diff = "N/A"
        pprint(role_one_diff)
    else:
        for permission in role_one_diff:
            pprint(permission)

    # Get the diff for role2
    role_two_diff = set(role_two_perms).difference(set(role_one_perms))

    print(f"\n # Role \"{role_two}\" differences:")
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
    try:
        with open(f"./roles/{role_name}", "r") as role_file:
            role_file = json.load(role_file)
            # Some roles do not have this key
            if "includedPermissions" in role_file:
                role_perms = role_file["includedPermissions"]
            else:
                role_perms = []

            return role_perms

    except FileNotFoundError as file_err:
        logging.error(f"Role not found. Check your spelling.")
        logging.debug(file_err)
        sys.exit(1)


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
    if shared_perms:
        print(
            f"\n # The shared permissions between {role_one} and {role_two} are: \n")
        for perms in shared_perms:
            pprint(perms)
    else:
        print("\n There are no shared permissions.")


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
        for perm in perms_list:
            pprint(perm)


def list_roles_for_perm(role_permission):
    """
    Lists all known GCP IAM roles that contain a specific permission.

    Args:
        role_permission (str): A GCP IAM permission.
    """

    # Before performing role analysis validate the permission
    # is formatted correctly
    validated = permission_validation(role_permission)

    # If permission is properly formatted get list of roles to analyze
    if validated:
        all_roles_names = get_all_role_names()
    else:
        logging.error(
            "All IAM permissions must be formatted \"service.resource.action\"")
        logging.error(f"You entered: {role_permission}")
        sys.exit(1)

    # Before finding roles remove special characters other than periods
    role_permission = format_permission(role_permission)

    # Empty list which we will add roles with permission to
    roles_with_perm = []

    # For each role name in our roles/ directory
    for role_name in all_roles_names:
        # We first get the list of permissions in the role
        role_perms = get_permissions(role_name)
        # Then we check for the specific permission in the list
        if role_permission in role_perms:
            roles_with_perm.append(role_name)

    # If there are roles with the specific permission
    if roles_with_perm:
        print(f"# The roles with the \"{role_permission}\" permission are: \n")
        for role in roles_with_perm:
            pprint(role)
    else:
        print(f"No roles found with permission \"{role_permission}\"")
        print("Check your spelling and capitalization.")


def permission_validation(role_permission):
    """
    Check the permission for 2 periods which is the IAM permission
    format.

    The format should always match "service.resource.action"
    ^^ statement is true as of Sept 25, 2022

    Args:
        role_permission (str): A GCP IAM permission.
    """

    num_periods = role_permission.count(".")
    if num_periods == 2:
        return True


def format_permission(role_permission):
    """
    Look for commas and remove.
    This is useful if a user passes in a list of permissions with commas

    Args:
        role_permission (str): A GCP IAM permission.
    """

    new_permission = re.sub(r",", "", role_permission)

    return new_permission


def get_all_role_names():
    """
    Gets a list of all IAM role names
    """

    try:
        role_names = os.listdir("roles/")
    except:
        logging.error("Could not list the \"roles/\" directory")
        raise

    return role_names


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
    parser.add_argument("-p", "--perm", nargs='+',
                        metavar="PERM", help="Lists roles which contain a specific permission.")
    parser.add_argument(
        "-r", "--refresh", help="Refreshes the local \"roles\" folder.", action='store_true')

    args = vars(parser.parse_args())

    # Check if user wants to download or refresh roles folder.
    if args["refresh"]:
        logging.info(
            "Refresh flag set, will refresh local \"roles\" folder and continue..")
        roles_refresh()
        print("Roles directory updated. \n")
        if not args["diff"] and not args["shared"] and not args["all"] and not args["list"]:
            print("Exiting - no further action requested.")
            sys.exit(0)

    # Require at least one argument
    if not args["diff"] and not args["shared"] and not args["all"] and not args["list"] and not args["perm"]:
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
            "Do you want to download the \"roles\" folder now? y/N \n")
        if refresh == "y":
            roles_refresh()
        elif refresh == "N":
            logging.info(
                "\"roles\" folder is required for analysis. Please execute with -r flag.")
        else:
            logging.error(
                f"Invalid or no input found. Value entered: \"{refresh}\"")

    inputs(args)

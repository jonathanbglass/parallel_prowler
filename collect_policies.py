import argparse
import boto3
import json
import logging
import os
from progressbar import ProgressBar
import sys

"""
Collects IAM Policies

Evaluates policies looking for badness (*.*, Effect:Allow + NotAction)

Need to add more tests/use cases
"""


def get_policies(profile):
    session = boto3.session.Session(profile_name=profile)
    myiam = session.client('iam')
    marker = None
    allPolicies = []
    passcount = 1
    while True:
        pbar = ProgressBar('Collecting Policies')
        print("Policy Collection, Pass Number: {}".format(passcount))
        passcount += 1
        if marker:
            response_iterator = myiam.list_policies(OnlyAttached=True,
                                                    Marker=marker)
        else:
            response_iterator = myiam.list_policies(OnlyAttached=True)
        for p in pbar(response_iterator['Policies']):
            polVers = myiam.get_policy_version(
                PolicyArn=p['Arn'], VersionId=p['DefaultVersionId'])
            mypol = {'Policy': p, 'PolicyVersion': polVers['PolicyVersion']}
            allPolicies.append(mypol)
            pfl = open(os.path.join('policies/', p['PolicyName']+'.json'), 'w')
            pfl.write(json.dumps(mypol, default=str, indent=4))
            pfl.close()
            ae = myiam.list_entities_for_policy(PolicyArn=p['Arn'])
            pfl = open(os.path.join('attachedentities/',
                                    p['PolicyName']+'.json'), 'w')
            pfl.write(json.dumps(ae, default=str, indent=4))
            pfl.close()
        try:
            marker = response_iterator['Marker']
        except KeyError:
            break
    print("\nTotal Policies: {}".format(len(allPolicies)))
    pbar = ProgressBar('\tChecking for Dangerous Policies')
    for p in pbar(allPolicies):
        # This section looks for bad/dangerous patterns

        # Pattern 1: Allow *.*

        # AWSLambdaRole {
        # 'Version': '2012-10-17',
        # 'Statement': [
        #   {'Effect': 'Allow',
        #   'Action': '*',
        #   'Resource': ['*']
        #   }
        # ]
        # }

        try:
            q = p['PolicyVersion']['Document']['Statement'][0]
        except Exception as e:
            print("Problem parsing this policy: {}".format(p))
            logging.debug("Problem parsing this policy: {}".format(p))
            print(e)
            continue
        try:
            if (q['Effect'] == "Allow" and '*' in q['Resource']
                    and '*' in q['Action']):
                print("Review Dangerous Policy: {} -> {}".format(
                    p['Policy']['PolicyName'],
                    p['PolicyVersion']['Document']))
        except Exception as e:
            pass

        # Pattern 2: Allow: *, NotAction

        # {'Version': '2012-10-17',
        # 'Statement': [
        #   {
        #       'Effect': 'Allow',
        #       'NotAction': ['iam:*', 'organizations:*', 'account:*'],
        #       'Resource': '*'
        #   },
        #   {
        #       'Effect': 'Allow',
        #       'Action': [ 'iam:CreateServiceLinkedRole',
        #                   'iam:DeleteServiceLinkedRole',
        #                   'iam:ListRoles',
        #                   'organizations:DescribeOrganization',
        #                   'account:ListRegions'
        #                 ],
        #       'Resource': '*'
        #   }
        # ]}
        # This policy blacklists all 'iam:*', 'organizations:*', and
        #   'accounts:*' with the NotAction. Then it grants specific
        #   access in the next stanza ('iam:ListRoles', etc)
        # The fatal flaw is that it grants access to everything else,
        # like lambda or ec2 because of the "Allow" in the first stanza.
        # This user can create an EC2 instance, attach an admin role to
        # it, and login and give themselves access to Admin. Instance
        # privilege escalation.
        try:
            if (q['NotAction'] and q['Effect'] == 'Allow'
                    and q['Resource'] == '*'):
                print("Review Suspect Policy: {} -> {}".format(
                    p['Policy']['PolicyName'],
                    p['PolicyVersion']['Document']))
        except Exception as e:
            pass
    return


def check_args_creds(args):
    # handle profiles / authentication / credentials
    workingCreds = False
    global logging
    global workingProfiles
    workingProfiles = []
    if not args.profile:
        logging.info("Using AWS Default Profile")
        if (not check_profile("default")):
            logging.error("Default credentials not working.")
            print("Default credentials not working.")
            quit()
        else:
            workingProfiles.append("default")
            workingCreds = True
    if args.profile and args.profile is not None:
        logging.info("Using " + args.profile + " Profile")
        if (not check_profile(args.profile)):
            logging.error("Profile " + args.profile + " not working")
            exit(1)
        else:
            logging.info("Profile " + args.profile + " working")
            workingProfiles.append(args.profile)
            workingCreds = True
    return args.profile


def check_profile(profile):
    global logging
    try:
        if(profile == "default"):
            client = boto3.session.Session()
        else:
            logging.info("Testing profile: " + profile)
            client = boto3.session.Session(profile_name=profile)
    except Exception as e:
        logging.error("Error connecting: ")
        logging.error(e)
        return False
    try:
        iam = client.client('iam')
        response = iam.list_users()
    except Exception as e:
        logging.error("Error listing users: ")
        logging.error(e)
        return False
    if len(response['Users']) == 0:
        logging.info("No users")
    if len(response) > 0:
        usercnt = len(response['Users'])
        if(usercnt > 1):
            userresp = " Users"
        else:
            userresp = " User"
        logging.info(str(usercnt) + userresp)
    return True


def setup_args(parser):
    parser.add_argument("-p", "--profile",
                        help="AWS Profile")
    parser.add_argument("-l", "--log",
                        help="Log Level")


def main():
    global logging
    parser = argparse.ArgumentParser()
    setup_args(parser)
    global args
    args = parser.parse_args()
    if args.log and args.log.upper() == "DEBUG":
        loglevel = "DEBUG"
    else:
        loglevel = "INFO"
    logging.basicConfig(filename='policyAssessment.log',
                        format='%(levelname)s:%(message)s',
                        level=loglevel)
    profile = check_args_creds(args)
    get_policies(profile)


if __name__ == "__main__":
    # execute only if run as a script
    main()

import boto3
import json
import os
import sys


def get_policies(profile):
    session = boto3.session.Session(profile_name=profile)
    myiam = session.client('iam')
    marker = None
    allPolicies = []
    while True:
        if marker:
            response_iterator = myiam.list_policies(OnlyAttached=True,
                                                    Marker=marker)
        else:
            response_iterator = myiam.list_policies(OnlyAttached=True)
        # print("Next Page: {} ".format(response_iterator['IsTruncated']))
        for p in response_iterator['Policies']:
            # pfl = open(os.path.join('policies/', p['PolicyName']+'.json'), 'w')
            # pfl.write(json.dumps(p, default=str, indent=4))
            # pfl.close()
            polVers = myiam.get_policy_version(
                PolicyArn=p['Arn'], VersionId=p['DefaultVersionId'])
            # print("DEBUG: polVers")
            # print(polVers)
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
            # print("DEBUG: Attached Entities")
            # print(ae)
            # print(json.dumps(polVers['polVers']['Document'], default=str))
        try:
            marker = response_iterator['Marker']
            # print(marker)
        except KeyError:
            break
    print("Total Policies: {}\n".format(len(allPolicies)))
    for p in allPolicies:
        # AWSLambdaRole {
        # 'Version': '2012-10-17',
        # 'Statement': [
        #   {'Effect': 'Allow',
        #   'Action': '*',
        #   'Resource': ['*']
        #   }
        # ]
        # }
        q = p['PolicyVersion']['Document']['Statement'][0]
        try:
            if (q['Effect'] == "Allow" and '*' in q['Resource']
                    and '*' in q['Action']):
                print("Review Dangerous Policy: {} -> {}".format(
                    p['Policy']['PolicyName'],
                    p['PolicyVersion']['Document']))
        except Exception as e:
            pass
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
    # pfl = open(os.path.join('debug/', 'allpolicies.csv'), 'w')
    # pfl.write("\n".join(allPolicies))
    # pfl.close()
    sys.exit(0)
    policies = myiam.list_policies(OnlyAttached=True)
    policies_file = open("policies_file.json", 'w')
    policies_file.write(json.dumps(policies, default=str))
    policies_file.close()
    thesepols = policies.get('Policies', [])
    print("Processing " + str(len(thesepols)) + " Policies")
    print(thesepols)
    i = 0
    for z in thesepols:
        # get policy document
        i += 1
        polVers = myiam.get_policy_version(PolicyArn=z['Arn'],
                                           VersionId=z['DefaultVersionId'])
        # get attached entities
        ae = myiam.list_entities_for_policy(PolicyArn=z['Arn'])
        print(json.dumps(polVers['polVers']['Document'], default=str))

        # insert policy metadata into database
        # polFile = open(str(i) + ".json", 'w')
        # json.dump(z, polFile, indent=4)
        # polFile.close()
        # cur.execute("EXECUTE policyplan "
        #             "(%s, %s, %s, %s, %s, %s, %s, %s, "
        #             "%s, %s, %s, %s, %s, %s, %s)",
        #             (accountid, json.dumps(z, default=str),
        #             z['DefaultVersionId'], z['IsAttachable'],
        #             z['AttachmentCount'], z['UpdateDate'],
        #             z['Path'], z['CreateDate'],
        #             z['PolicyName'], z['PolicyId'],
        #             z['Arn'],
        #             json.dumps(polVers['polVers']['Document'], default=str),
        #             json.dumps(ae['PolicyGroups'], default=str),
        #             json.dumps(ae['PolicyUsers'], default=str),
        #             json.dumps(ae['PolicyRoles'], default=str)))
    return


def main():
    get_policies('default')


if __name__ == "__main__":
    # execute only if run as a script
    main()

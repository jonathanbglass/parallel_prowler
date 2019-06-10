import boto3
import json
import sys


def get_policies(profile):
    session = boto3.session.Session(profile_name=profile)
    myiam = session.client('iam')
    marker = None
    while True:
        if marker:
            response_iterator = myiam.list_policies(OnlyAttached=True,
                                                    Marker=marker)
        else:
            response_iterator = myiam.list_policies(OnlyAttached=True)
        print("Next Page : {} ".format(response_iterator['IsTruncated']))
        for p in response_iterator['Policies']:
            print(p)

        try:
            marker = response_iterator['Marker']
            print(marker)
        except KeyError:
            sys.exit()

    sys.exit()
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
    get_policies('CCNA_BI_PROD_Auditor')
    get_policies('CCNA_BI_NONPROD_Auditor')


if __name__ == "__main__":
    # execute only if run as a script
    main()

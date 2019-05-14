import argparse
import boto3
import csv
import json
import logging
import mmap
import numpy as np
import os
import pandas as pd
import queue
from shlex import quote
import subprocess
import sys
import threading
import time
import uuid


def setup_args(parser):
    parser.add_argument("-p", "--profile",
                        help="AWS Profile")
    parser.add_argument("-pp", "--prowlerPath",
                        help="Path to Prowler Executable. "
                        "Defaults to ./prowler/prowler")
    parser.add_argument("-pc", "--prowlerCheck",
                        help="Single or List of Prowler Check(s) [check11]")
    parser.add_argument("-pg", "--prowlerGroup",
                        help="Group of Prowler Checks [cislevel2]")
    parser.add_argument("-pE", "--prowlerExclude",
                        help="Execute all tests except a list of specified "
                        "checks separated by comma (i.e. check21,check31)")
    parser.add_argument("-R", "--region",
                        help="AWS Region")
    parser.add_argument("-r", "--regex",
                        help="REGEX Pattern to Identify AWS Profiles")
    parser.add_argument("-o", "--outputDir",
                        help="Output Directory")
    # parser.add_argument("-o", "--organization",
    #                     help="AWS Profile for Organization Account")
    parser.add_argument("-t", "--maxthreads", type=int,
                        help="Max threads: defaults to # of CPUs")
    parser.add_argument("-F", "--resultsFile", type=str,
                        help="Results CSV to process to a report XLSX file")
    parser.add_argument("-l", "--log", type=str,
                        choices=['info', 'INFO', 'debug', 'DEBUG'],
                        help="Set LogLevel to INFO (Default) or DEBUG")
    parser.add_argument("-v", "--verbosity", type=int, choices=[0, 1],
                        help="increase output verbosity")


def check_args_debug(args):
    # Handle logging
    global outputDir
    global logging
    if args.log and args.log.upper() == "DEBUG":
        loglevel = "DEBUG"
    else:
        loglevel = "INFO"
    logging.basicConfig(filename=outputDir + '/' + 'assessment.log',
                        format='%(levelname)s:%(message)s',
                        level=loglevel)


def check_args_prowlerPath(args):
    # Handle prowlerPath
    global logging
    global prowlerPath
    if args.prowlerPath and os.path.exists(args.prowlerPath):
        prowlerPath = args.prowlerPath
    else:
        if not os.path.exists("./prowler/prowler"):
            print("Prowler not found. Install or clone the repository into "
                  "this directory or provide the path with -pp, --prowlerPath")
            quit()
        else:
            prowlerPath = "./prowler/prowler"


def check_args_verbosity(args):
    # handle verbosity
    global logging
    global verbose
    if args.verbosity == 1:
        verbose = True
        logging.info("Verbose")
    else:
        verbose = False
        logging.info("No Verbosity")


def check_args_creds(args):
    # handle profiles / authentication / credentials
    workingCreds = False
    global logging
    global verbose
    global workingProfiles
    workingProfiles = []
    if not args.profile and not args.regex:
        logging.info("Using AWS Default Profile")
        if verbose:
            print("Using AWS Default Profile")
            print(args.profile)
        if (not check_profile("default")):
            logging.error("Default credentials not working.")
            print("Default credentials not working.")
            quit()
        else:
            workingProfiles.append("default")
            workingCreds = True
    if args.profile and args.profile is not None:
        logging.info("Using " + args.profile + " Profile")
        if verbose:
            print("Using " + args.profile + " Profile")
        if (not check_profile(args.profile)):
            logging.error("Profile " + args.profile + " not working")
            if verbose:
                print("Profile " + args.profile + " not working")
                quit()
        else:
            logging.info("Profile " + args.profile + " working")
            if verbose:
                print("Profile " + args.profile + " working")
            workingProfiles.append(args.profile)
            workingCreds = True


def check_args_regex(args):
    global logging
    global verbose
    if not args.regex:
        logging.info("No REGEX Pattern. Working on a single account.")
        if verbose:
            print("No REGEX Pattern. Working on a single account.")
    else:
        # To Do: turn these variable into arguments
        configFile = "~/.aws/config"
        credFile = "~/.aws/credentials"
        profileCount = 0
        if os.path.exists(os.path.expanduser(configFile)):
            configFileContent = open(
                os.path.expanduser(configFile), 'r').read()
        else:
            logging.error("AWS Config file unreadable")
            print("AWS Config file unreadable")
            quit()
        if args.regex in configFileContent:
            logging.info("REGEX found")
            if verbose:
                print("REGEX found")
            for x in configFileContent.split("\n"):
                if "[profile" in x and args.regex in x:
                    profileCount += 1
                    thisProfile = x.strip('[]').split(" ")[1]
                    logging.debug("Checking profile: " + thisProfile)
                    if verbose:
                        print("Checking profile: " + thisProfile)
                    if (check_profile(thisProfile)):
                        logging.debug("Profile " + thisProfile + " works.")
                        if verbose:
                            print("Profile " + thisProfile + " works.")
                        workingProfiles.append(thisProfile)
                    else:
                        logging.debug("Profile " + thisProfile
                                      + " does not work.")
                        if verbose:
                            print("Profile " + thisProfile + " does not work.")

            if (profileCount > 1) or (profileCount == 0):
                profresp = (str(profileCount) + " Profiles found. "
                            + str(len(workingProfiles)) + " Profiles work.")
            else:
                profresp = str(profileCount) + " Profile found and works"
            if(len(workingProfiles) == 0):
                logging.error("No working profiles, REGEX: " + str(args.regex))
                print("No working profiles for REGEX: " + str(args.regex))
                quit()
            print(profresp)
            logging.info(profresp)
        else:
            logging.error("REGEX " + str(args.regex)
                          + " not found in " + configFile)
            print("REGEX " + str(args.regex) + " not found in " + configFile)
            quit()


def check_args_outputDir(args):
    global logging
    global outputDir
    outputDir = os.path.abspath(os.curdir)
    if args.outputDir:
        if not os.path.exists(args.outputDir):
            print("Output Directory Does Not Exist: " + args.outputDir)
            quit()
        else:
            outputDir = os.path.abspath(args.outputDir)


def process_args(args):
    check_args_outputDir(args)
    check_args_debug(args)
    check_args_verbosity(args)
    check_args_prowlerPath(args)
    check_args_creds(args)
    check_args_regex(args)


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


def run_prowler(x):
    global args
    global logging
    global outputDir
    global prowlerPath
    global resultDict
    global verbose
    logging.debug("Inside run_prowler: " + x)
    if verbose:
        print("Inside run_prowler: " + x)
    cmd = os.path.realpath(prowlerPath)
    cmdopts = ' -p {}'.format(quote(x))
    if args.region:
        cmdopts += ' -r {}'.format(quote(args.Region))
    else:
        cmdopts += ' -r us-east-1'
    if args.prowlerExclude:
        cmdopts += ' -E {}'.format(quote(args.prowlerExclude))
    cmdopts += ' -n'
    cmdopts += ' -b -M csv'
    if args.prowlerCheck is not None:
        cmdopts += ' -c {}'.format(quote(args.prowlerCheck))
    if args.prowlerGroup is not None:
        cmdopts += ' -g {}'.format(quote(args.prowlerGroup))
    logging.info(cmd+cmdopts)
    if verbose:
        print(cmd+cmdopts)
    p = subprocess.run([cmd + cmdopts], shell=True, text=True, check=False,
                       capture_output=True)
    logging.debug("Inside run_prowler - subprocess: ")
    logging.info(p)
    if verbose:
        print("Inside run_prowler - subprocess")
        print(p)
    resultDict[x] = p.stdout
    fname = 'prowler-' + str(int(scanTime)) + '-' + str(scanUUID)\
        + '-' + quote(x) + '.csv'
    fname = outputDir + '/' + fname
    f = open(fname, 'w')
    f.write(p.stdout)
    f.close()


def worker():
    global logging
    global q
    global resultDict
    global verbose
    while True:
        x = q.get()
        if x is None:  # EOF?
            return
        else:
            logging.debug("Inside worker: " + x)
            if verbose:
                print("Inside worker: " + x)
        run_prowler(x)


def check_args_organizations(args):
    global logging
    pass
    # # Handle Organizations and use it to create list of accounts to audit
    # if not args.organization:
    #     logging.info("No AWS Organization Account")
    #     if verbose:
    #         print("No AWS Organization Account")
    # else:
    #     print("Not implemented yet")


def get_col_widths(dataframe, index):
    # First we find the maximum length of the index column
    if index:
        idx_max = max([len(str(s)) for s in dataframe.index.values]
                      + [len(str(dataframe.index.name))])
        return [idx_max] + [max([len(str(s)) for s in dataframe[col].values]
                                + [len(col)]) for col in dataframe.columns]
    else:
        # Then, we concatenate this to the max of the lengths of column name
        # and its values for each column, left to right
        return [max([len(str(s)) for s in dataframe[col].values]
                    + [len(col)]) for col in dataframe.columns]


def process_results(resultFileName):
    global args
    global logging
    if 'verbose' in globals():
        verbose = True
    else:
        verbose = False
    if args.resultsFile:
        excelName = args.resultsFile.split('.')[0] + '.xlsx'
    else:
        excelName = 'results-'+str(int(scanTime))+'-'+str(scanUUID)+'.xlsx'
    if 'outputDir' in globals():
        excelName = outputDir + '/' + excelName
    p_df = pd.read_csv(resultFileName,
                       dtype={'ACCOUNT_NUM': str, 'TITLE_ID': str})
    if verbose:
        print(p_df.shape)
        print(p_df)
    writer = pd.ExcelWriter(excelName, engine='xlsxwriter')
    workbook = writer.book

    # Write Summary first
    q3 = ('(LEVEL == "Level 1" or LEVEL == "Level 2") and '
          '(RESULT == "PASS" or RESULT == "FAIL")')
    p_df_pass = p_df.query(q3)
    if verbose:
        print(p_df_pass)
    p_df_pass.groupby(['PROFILE', 'ACCOUNT_NUM', 'RESULT'])['RESULT'].count().to_excel(writer, sheet_name="Summary")
    worksheet = writer.sheets['Summary']
    for i, width in enumerate(get_col_widths(p_df, False)):
        worksheet.set_column(i, i, width)

    # Write raw results to Excel
    p_df.to_excel(writer, sheet_name='RawResults', index=False)
    worksheet = writer.sheets['RawResults']
    for i, width in enumerate(get_col_widths(p_df, False)):
        worksheet.set_column(i, i, width)

    # Write Passing results to Excel
    q1 = 'RESULT == "PASS"'
    p_df_pass = pd.pivot_table(
        p_df.query(q1),
        index=['TITLE_ID', 'TITLE_TEXT'],
        columns=['PROFILE', 'ACCOUNT_NUM'], values='RESULT',
        aggfunc=np.count_nonzero, fill_value=0)
    p_df_pass.to_excel(writer, sheet_name="All Passing")

    # Write Failing results to Excel
    q2 = 'RESULT == "FAIL"'
    p_df_fail = pd.pivot_table(
        p_df.query(q2),
        index=['TITLE_ID', 'TITLE_TEXT'],
        columns=['PROFILE', 'ACCOUNT_NUM'], values='RESULT',
        aggfunc=np.count_nonzero, fill_value=0)
    p_df_fail.to_excel(writer, sheet_name="All Failing")

    # Write CIS Benchmarks Passing results to Excel
    q3 = 'RESULT == "PASS" and (LEVEL == "Level 1" or LEVEL == "Level 2")'
    p_df_cis_pass = pd.pivot_table(
        p_df.query(q1),
        index=['TITLE_ID', 'LEVEL', 'SCORED', 'TITLE_TEXT'],
        columns=['PROFILE', 'ACCOUNT_NUM'], values='RESULT',
        aggfunc=np.count_nonzero, fill_value=0)
    p_df_cis_pass.to_excel(writer, sheet_name="CIS Benchmarks Passing")

    # Write CIS Benchmarks failing results to Excel
    q4 = 'RESULT == "FAIL" and (LEVEL == "Level 1" or LEVEL == "Level 2")'
    p_df_cis_fail = pd.pivot_table(
        p_df.query(q2),
        index=['TITLE_ID', 'LEVEL', 'SCORED', 'TITLE_TEXT'],
        columns=['PROFILE', 'ACCOUNT_NUM'], values='RESULT',
        aggfunc=np.count_nonzero, fill_value=0)
    p_df_cis_fail.to_excel(writer, sheet_name="CIS Benchmarks Failing")

    print("Report Excel File: " + excelName)
    writer.save()


def main():
    global logging
    parser = argparse.ArgumentParser()
    setup_args(parser)
    global args
    args = parser.parse_args()
    if not args.resultsFile:
        process_args(args)
        global resultDict
        resultDict = {}
        global scanUUID
        global scanTime
        # Generate a Testing UUID and TimeStamp to add to logs / results
        scanUUID = uuid.uuid4()
        scanTime = time.time()
        logging.info(scanUUID)
        logging.info(int(scanTime))
        if verbose:
            print(scanUUID)
            print(int(scanTime))

        # setting up queues

        global q
        q = queue.Queue()

        # process workingProfiles, run assessment tool(s) against each Profile
        for x in workingProfiles:
            q.put(x)
        if args.maxthreads and args.maxthreads > 0:
            maxthreads = int(args.maxthreads)
        else:
            maxthreads = psutil.cpu_count(logical=False)
        threads = [threading.Thread(target=worker) for _i in range(maxthreads)]
        for thread in threads:
            thread.start()
            q.put(None)  # one EOF marker for each thread

        for thread in threads:
            thread.join()

        header = False
        resultFileName = 'results-'+str(int(scanTime))+'-'+str(scanUUID)+'.csv'
        resultFileName = outputDir + '/' + resultFileName
        print("Opening CSV")
        resultFile = open(resultFileName, 'w+')
        for key in resultDict:
            print("resultDict Key: " + key)
            print("Value:")
            print(resultDict[key])

            for i in range(len(resultDict[key].split('\n'))):
                if header:
                    if 'ACCOUNT_NUM' not in resultDict[key].split('\n')[i]:
                        resultFile.write(resultDict[key].split('\n')[i] + "\n")
                else:
                    print("Writing Headers")
                    resultFile.write(resultDict[key].split('\n')[0] + "\n")
                    header = True
        resultFile.close()
        print("Result File: " + resultFileName)
        process_results(resultFileName)
    else:
        if os.path.exists(args.resultsFile):
            process_results(args.resultsFile)
        else:
            print('File unreadable: ' + str(args.resultsFile))
            log.error('File unreadable: ' + str(args.resultsFile))


if __name__ == "__main__":
    # execute only if run as a script
    main()

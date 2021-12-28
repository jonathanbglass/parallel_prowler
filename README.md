# parallel_prowler

## Purpose
* Runs Prowler in parallel across multiple AWS accounts (one thread per account)
* Writes the results per account into a CSV file
* Writes combined raw results from all tests into a single CSV file
* Generates a summary report across all accounts in an Excel XLSX file

## Installation
* Requires Python 3+
```$ git clone https://github.com/jonathanbglass/parallel_prowler
$ python3.7 -m venv parallel_prowler/
$ source ./parallel_prowler/bin/activate
$ cd parallel_prowler
$ pip install -r requirements.txt
$ git clone https://github.com/toniblyx/prowler
$ python parallel_prowler.py -h
```


## Command line options
```
usage: parallel_prowler.py [-h] [-p PROFILE] [-pp PROWLERPATH]
                           [-pc PROWLERCHECK] [-pg PROWLERGROUP]
                           [-pE PROWLEREXCLUDE] [-R REGION] [-r REGEX]
                           [-o OUTPUTDIR] [-t MAXTHREADS] [-F RESULTSFILE]
                           [-l {info,INFO,debug,DEBUG}] [-v {0,1}]

optional arguments:
  -h, --help            show this help message and exit
  -p PROFILE, --profile PROFILE
                        AWS Profile
  -pp PROWLERPATH, --prowlerPath PROWLERPATH
                        Path to Prowler Executable. Defaults to
                        ./prowler/prowler
  -pc PROWLERCHECK, --prowlerCheck PROWLERCHECK
                        Single or List of Prowler Check(s) [check11]
  -pg PROWLERGROUP, --prowlerGroup PROWLERGROUP
                        Group of Prowler Checks [cislevel2]
  -pE PROWLEREXCLUDE, --prowlerExclude PROWLEREXCLUDE
                        Execute all tests except a list of specified checks
                        separated by comma (i.e. check21,check31)
  -R REGION, --region REGION
                        AWS Region
  -r REGEX, --regex REGEX
                        REGEX Pattern to Identify AWS Profiles
  -o OUTPUTDIR, --outputDir OUTPUTDIR
                        Output Directory
  -t MAXTHREADS, --maxthreads MAXTHREADS
                        Max threads: defaults to # of CPUs
  -F RESULTSFILE, --resultsFile RESULTSFILE
                        Results CSV to process to a report XLSX file
  -l {info,INFO,debug,DEBUG}, --log {info,INFO,debug,DEBUG}
                        Set LogLevel to INFO (Default) or DEBUG
  -v {0,1}, --verbosity {0,1}
                        increase output verbosity

```
* Note: `-p` and `-r` are mutually exclusive options. `-p` provides a single AWS profile to use, while `-r` provides a pattern to search for in profile names.

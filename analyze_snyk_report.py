#!/usr/bin/env python3

import argparse
import pandas as pd

# Initialize parser
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--Input", help = "Path to snyk report file")
args = parser.parse_args()

if args.Input:
    report_file="log4j_vulnerabilities.csv"
    print("Analyzing snyk Report")
    csv_file = args.Input
    data = pd.read_csv(csv_file)
    headers = ['issue.package','issue.version','issue.identifiers.CVE','issue.severity','project.name']
    data = data[headers]
    
    cve_values = ['["CVE-2021-4104"]','["CVE-2017-5645"]','["CVE-2020-9488"]','["CVE-2019-17571"]','["CVE-2021-44228"]','["CVE-2021-45046"]']
    data = data[data['issue.identifiers.CVE'].isin(cve_values)]

    # Get the number of rows and columns
    rows = len(data.axes[0])
    cols = len(data.axes[1])
    print("Rows: " + str(rows) + " | Columns: "+ str(cols))
    data.to_csv(report_file,index=False)
    print("Report Generation Done !!!")
    print("Report -> "+report_file)
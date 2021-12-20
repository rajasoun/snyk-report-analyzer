#!/usr/bin/env bash

csv_file="$1"
lg4j_cve="CVE-2021-4104|CVE-2017-5645|CVE-2020-9488|CVE-2019-17571|CVE-2021-44228|CVE-2021-45046|CVE-2021-45046"
headers="$(cat  $csv_file | head -1)"
vuln_repos="$(grep -E $LOG4J_SEARCH_PATTERN $INPUT)"
echo "$headers" > log4j_vulnerabilities.csv
echo "$vuln_repos" >> log4j_vulnerabilities.csv


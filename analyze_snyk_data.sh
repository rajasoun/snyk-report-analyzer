#!/usr/bin/env bash


LOG4J_SEARCH_PATTERN="CVE-2021-4104|CVE-2017-5645|CVE-2020-9488|CVE-2019-17571|CVE-2021-44228|CVE-2021-45046|CVE-2021-45046"
INPUT="issues-cisco-lcande-pilot-ghe-2021-12-20T08_47_55.466Z.csv"
headers="$(cat  $INPUT | head -1)"
VULNERABILE_REPOS="$(grep -E $LOG4J_SEARCH_PATTERN $INPUT)"
echo "$headers" > /tmp/vul.csv
echo "$VULNERABILE_REPOS" >> /tmp/vul.csv



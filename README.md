
# Carbon Black Cloud extractor

This Python3 script extracts events from the Carbon Black Cloud. It currently supports extracting EnrichedEvents, Process information, and Process Events (modload, filemod, netconn, childproc, crossproc). It outputs the result to both CSV and JSON.

![](example.gif)

&nbsp;
## Use cases

- Extracting all events of one system for an offline investigation
- Extracting process events with parameters as it is not feassible using the GUI
- Extracting detailed events: netconn, filemod, modload, childproc, crossproc
- Probably more

&nbsp;
## Installation

Place API key details in `C:/Users/User/.carbonblack/credentials.cbc`:

```
[default]
url=https://defense-eu.conferdeploy.net
token=XXXXXXXXXXXXXXXXXXXXXXXX/XXXXXXXXXX
org_key=XXXXXXXX
ssl_verify=yes
ssl_verify_hostname=yes
```

Install requirements:
`pip3 install -r requirements.txt`

&nbsp;
## Usage

Extract all supported events of system named 'desktop-x' of the last 2 days:  

`cbc_extractor.py --query device_name:desktop-x --window='-2d'`

Extract all supported events between two dates:  

`cbc_extractor.py --query device_name:desktop-x --starttime 2023-04-04T00:00:00+00:00 --endtime 2023-04-05T00:00:00+00:00`

When a script stops unexpectedly - for example due to network issues - you can rerun the script:

`cbc_extractor.py --re_run 2023-04-11_160540_results.log`

Extract only events of the type ProcessEvents:

`cbc_extractor.py --query 'process_guid:XXXXXXXXXX-008fd4db-0000040c-00000000-1d95fdeffc5a8d5' --window='-4w' --eventtypes ProcessEvents`

Extract events of the last year, and run the script in the background:

`nohup python3 CB.py --query device_name:server-x --window='-1y' &`

&nbsp;
## known issues

- Due to API limitations the end-count differs of extracted process events (netconn, filemod etc). This issue was logged at VMware but until date no solution was provided.
- Script is not suitable for extracting all Carbon Black Cloud events for each and every system. If you want to do that forward to an S3 bucket.

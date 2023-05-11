
# Carbon Black Cloud extractor

This Python3 script extracts events from the Carbon Black Cloud. It currently supports extracting EnrichedEvents, Process information, and Process Events (modload, filemod, netconn, childproc, crossproc). 

![](example.gif)

The result is outputed to both CSV and JSON.

- 2023-05-11_143617_results_EnrichedEvent.csv
- 2023-05-11_143617_results_ProcessEvent.csv
- 2023-05-11_143617_results_Process.csv
- 2023-05-11_143617_results.json

&nbsp;
## Use cases

- Extracting detailed Carbon Black Cloud events
- Conduct timeline analysis of adversary behaviour using Carbon Black Cloud events
- Store Carbon Black Cloud events offline for later investigation
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
## Limitations

- Script is not suitable for extracting Carbon Black Cloud events of 1000's of systems. If you want to do that forward to an S3 bucket.

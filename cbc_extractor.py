#!/usr/bin/python3

__author__ = 'DfirJos'
__version__ = '2.1'
__date__ = 'March 30, 2023'

import time
import json
import re
import logging as log
import sys
import csv
from logging import config
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import argparse
    from argparse import RawTextHelpFormatter
    from cbc_sdk import CBCloudAPI
    from cbc_sdk.endpoint_standard import EnrichedEvent
    from cbc_sdk.platform import Process
    import cbc_sdk.enterprise_edr
except Exception as e:
    log.error('Error loading libary: %s. Install libraries via pip3 install -r requirements.txt' %e)
    exit()

scriptname = sys.argv[0]
def_eventtypes = ['EnrichedEvent', 'Process', 'ProcessEvent']
parser = argparse.ArgumentParser(description =  
f'''
This script extracts events from a Carbon Black Cloud instance using the API. 
It supports extracting EnrichedEvents, Process information, and Process Events (modload, filemod, netconn, childproc, crossproc).

Examples:
    {scriptname} --query device_name:desktop-x --window='-1y'
    {scriptname} --query device_name:desktop-x --starttime 2023-04-04T00:00:00+00:00 --endtime 2023-04-05T00:00:00+00:00
    {scriptname} --re_run 2023-04-11_160540_results.log # to restart a failed run.
    {scriptname} --query 'process_guid:XXXXXXXXXX-008fd4db-0000040c-00000000-1d95fdeffc5a8d5' --window='-4w' --eventtypes ProcessEvents
''' 
    ,formatter_class=RawTextHelpFormatter)
parser.add_argument('-v', '--verbose', help='Display verbose events to stdout.', action='store_true')
parser.add_argument('-q', '--query', help='Provide the query you want to launch', default=None)
parser.add_argument('-p', '--pagination', help='The time period in minutes used to paginate the extraction of logs', default=360, type=int)
parser.add_argument('-o', '--output', help='Output file.', required=False, default=f'{datetime.now():%Y-%m-%d_%H%M%S}_results.json')
parser.add_argument('-e', '--eventtypes', help='The eventtypes you want to download. Example: --eventtypes Process EnrichedEvent', nargs='+', default=def_eventtypes, choices=def_eventtypes)
parser.add_argument('-w', '--window', help='Time window to execute the result search. Should be in the form \'-2w\', where y=year, w=week, d=day, h=hour, m=minute, s=second', default=None)
parser.add_argument('-r', '--re_run', help='Re-run a failed query. Provide the log file. Example: --re_run=2023-04-11_160540_results.log', default=None)
parser.add_argument('-st', '--starttime', help='Used to specify starttime of the data you want to query. Example: --starttime 2023-04-04T00:00:00+00:00', default='2023-04-04T00:00:00+00:00')
parser.add_argument('-et', '--endtime', help='Used to specify endtime of the data you want to query. Example: --endtime 2023-04-05T00:00:00+00:00', default='2023-04-05T00:00:00+00:00')
parser.add_argument('-sl', '--skip_log', help='Skip writing a log file.', action='store_false')
parser.add_argument('-sc', '--skip_csv', help='Skip converting json to csv files.', action='store_false')
parser.parse_args(args=None if sys.argv[1:] else ['--help'])
args = parser.parse_args()

query = args.query
pagination = args.pagination
output = args.output
eventtypes = args.eventtypes
starttime = args.starttime
endtime = args.endtime
window = args.window
re_run = args.re_run
skip_csv = args.skip_csv
now = datetime.now()
utctime = now.astimezone(timezone.utc)
events = defaultdict(dict)
cache = defaultdict(dict)
endtimes = {}
starttimes = {}
starttime_script = time.time()
logfile = output.replace('.json', '.log')

if args.verbose:
    verb = 'DEBUG'
else:
    verb = 'INFO'

if args.skip_log:
    log_handler = ["console", "file"]
else:
    log_handler = ["console"]

if args.re_run:
    logfile = re_run
    output = re_run.replace('.log', '.json')
   
log_config = {
    "version":1, 
    "root": {
        "handlers" : log_handler,
        "level": "DEBUG"
    },
    "handlers": {
        "console": {
            "formatter": "std_out",
            "class": "logging.StreamHandler",
            "level": verb
        },
        "file": {
            "formatter": "std_out",
            "class": "logging.FileHandler",
            "level": "INFO",
            "filename": logfile
        }
    },
    "formatters": {
        "std_out": {
            "format": "%(asctime)s | %(levelname)s | %(message)s",
            "datefmt": "%Y-%m-%d %I:%M:%S"
        }
    },
}

config.dictConfig(log_config)
log.info('Script started. Logging everything to %s' % logfile)
log.debug('Debugging flag set via -v')

def main():

    global endtime, starttime, endtime, query, eventtypes, re_run, pagination

    cb = readcredsfile()

    if window:
        starttime = str(timecalc(window, utctime))
        endtime = str(utctime)

    finished = []
    if re_run:
        if not re_run.endswith('.log'):
            log.error('This file does not seem to be a log-file: %s.' % re_run)
            log.info('Script will exit.')
            exit()
        if re_run.endswith('.log'):
            log.info('Re-running failed queries in log: %s' % re_run)
            for line in open(re_run).readlines():
                pass
            last_line = line
            re_finished = re.search('Script finished.', last_line)
            if re_finished:
                log.error('Script already finished, no need to re-run it.')
                log.info('Script will exit.')
                exit()

            linenr = 0
            for line in open(re_run).readlines():
                linenr += 1
                if linenr < 4:
                    re_query = re.findall(r'\"(.*?)\"', line)
                    if re_query:
                        if len(re_query) == 5:
                            query, starttime, endtime, eventtypes, pagination = re_query
                            pagination = int(pagination)
                            eventtypes = eventtypes.split(', ')
                            log.info('Found the query details in file %s' % re_run)
                        else:
                            log.error('Did not find the query details in %s.' % re_run)
                            log.info('Script will exit.')
                            exit()

                re_finished = re.search('Query ([0-9]+) (finished|contains 0 events)', line)
                if re_finished:
                    re_finished = int(re_finished.group(1))
                    if re_finished not in finished:
                        finished.append(re_finished)

    jobnr = 0    
    stop = datetime.fromisoformat(endtime)
    futures = []
    log.info('Query details: \"%s\" from \"%s\" to \"%s\" with eventtypes: \"%s\" and pagination \"%s\".' % (query, starttime, endtime, ', '.join(eventtypes), pagination))
    with ThreadPoolExecutor(max_workers=10) as executor, open(output, 'a') as stream:

        for eventtype in eventtypes:
            
            starttimes[eventtype] = datetime.fromisoformat(str(starttime))
            events[eventtype] = []

            while True:

                jobnr += 1
                endtimes[eventtype] = starttimes[eventtype] + timedelta(minutes=pagination)
                if endtimes[eventtype] > stop:
                    endtimes[eventtype] = stop

                if jobnr not in finished:
                    log.info('Query %s launched. Querydetails: %s, eventtype: %s, starttime: %s, endtime: %s' % (jobnr, query, eventtype, starttimes[eventtype], endtimes[eventtype]))
                    futures.append(executor.submit(async_query, cb, starttimes[eventtype], endtimes[eventtype], query, eventtype, jobnr))
                else:
                    log.info('Skipping query %s as it was either empty or already written to: %s' %(jobnr, output))

                starttimes[eventtype] = starttimes[eventtype] + timedelta(minutes=pagination)

                if endtimes[eventtype] >= stop:
                    log.info('All queries of eventtype %s were launched.' % eventtype)
                    break
  
        eventnr  = 0
        jobs_max, jobs_failed = [],[]
        job = None
        for future in as_completed(futures):
            try:
                job = future.result()
            except Exception as e:
                jobnr = vars(future)['_result'][1]
                jobs_failed.append(jobnr)
                log.error('Could not retrieve results of query %s: %%' % (jobnr, e))

            if isinstance(job, tuple):
                maximum_reached = job[3]
                eventtype = job[2]
                jobnr = job[1]
                job = job[0]
                if not maximum_reached:
                    for t in job:
                        eventnr += 1
                        t['custom_eventtype'] = eventtype
                        json.dump(t, stream)
                        stream.write('\n')
                        log.debug('Event written to log file %s : %s ' %(t, output))
                    log.info('Query %s finished and results are written to: %s.' % (jobnr, output))
                if maximum_reached:
                    jobs_max.append(jobnr)
     
            log.debug('Removing query %s from Futures list.' % jobnr)
            index = futures.index(future)
            futures.pop(index)

    if eventnr >= 1:
        log.info('Written a total of %s queries containing %s events to file: %s in %s seconds' % (jobnr, eventnr, output, time.time() - starttime_script))
        log.info('Deduplicating rows in %s' % output)
        uniquelines = set(open(output).readlines())
        open(output, 'w').writelines(uniquelines)
        new = sum(1 for line in open(output))
        log.info('Total lines after deduplication: %s (%s removed) in file %s' % (new, eventnr - new, output))

        if skip_csv:
            log.info('Argument \'--skip_csv\' was not used. Writing to CSV files.')
            output_csv = output.replace('.json', '.csv')
            dictio = defaultdict(list)      
            header = defaultdict(set)
            count = defaultdict(int)
            with open(output, 'r') as reader:
                for line in reader:
                    line_json = json.loads(line)
                    dictio[line_json['custom_eventtype']].append(line_json)
                    for i in line_json.keys():
                        header[line_json['custom_eventtype']].add(i)

            for eventtype in header.keys():
                output_splitcsv = output_csv.replace('.csv', '_' +  eventtype + '.csv')
                
                with open(output_splitcsv, 'w', newline='') as file:
                    writer = csv.DictWriter(file, fieldnames=header[eventtype])
                    writer.writeheader()
                    for row in dictio[eventtype]:
                        count[eventtype] += 1
                        writer.writerow(row)

                log.info('%s events written to %s.' % (count[eventtype], output_splitcsv))

    if eventnr < 1:
        log.info('No events written to %s.' % output )

    jobs_failed_length = len(jobs_failed)
    if jobs_failed_length >= 1:
        log. error('Queries %s failed. Check log-file for error.' % str(jobs_max)[1:-1] )

    jobs_max_length = len(jobs_max)
    if jobs_max_length >= 1:
        log.error('Queries %s reached the maximum number of events. Consider re-launching the script with a lower pagination. Example: --pagination %s' % (str(jobs_max)[1:-1], int(pagination / 2)))

    log.info('Total execution time of script: %s seconds' % (time.time() - starttime_script))
    log.info('Script finished.')
    log.info('Exiting script.')
    

def async_query(cb, starttime, endtime, query, eventtype, jobnr):

    maximum_count = 0
    data = []
    eventtype_original = eventtype
    eventtype = eventtype.replace('ProcessEvent', 'Process')
    starttime_query = time.time()

    try:
        query_events = cb.select(eventtype).where(query).set_rows(10000).set_time_range(start=starttime.isoformat(), end=endtime.isoformat())
        log.info('Query %s started.' % jobnr)
    except Exception as e:
        query_events = None
        log.error('Failed to start query %s. Error: %s' % (jobnr, e))

    if query_events:
        for event in query_events:
            try:
                if eventtype_original == 'EnrichedEvent':
                    maximum_count += 1
                    i = event.original_document
                    if i:
                        data.append(i)

                if eventtype_original == 'Process':
                    maximum_count += 1
                    i = vars(event)['_info']
                    data.append(i)

            except Exception as e:
                log.error('Error when retrieving event of type %s from query %s: %s' % (eventtype_original, jobnr, e) )

            if eventtype_original == 'ProcessEvent':
                for i in event.events():
                    try:
                        i = i.original_document
                        fields = ['netconn_remote_ipv4','netconn_local_ipv4']
                        for field in fields:
                            if i.get(field) and type(int):
                                ipstr = to_string(i[field])
                                log.debug('Query %s. Converting %s to %s.' % (jobnr, i[field], ipstr))
                                i[field] = ipstr
                        data.append(i)
                    except Exception as e:
                        log.error('Error when retrieving event of type ProcessEvent of query %s: %s' % (jobnr, e) )

    if maximum_count == 10000:
        log.error('Query %s reached a maximum of 10.000 events.' % jobnr)
        maximum_reached = True
    else:
        maximum_reached = False

    if data:
        length = len(data)
    else:
        length = 0

    endtime_query = time.time() - starttime_query
    log.info('Query %s contains %s events of type %s. Duration %s seconds.' % (jobnr, length, eventtype_original, endtime_query))

    return data, jobnr, eventtype_original, maximum_reached


def to_string(ip):
    # https://gist.github.com/cslarsen/1595135 
    #"Convert 32-bit integer to dotted IPv4 address."
    return ".".join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))


def timecalc(window, utctime):

    window = window.strip('\'')
    number = int(re.findall(r'\d+', window)[0])

    if window.endswith('y'):
        number = number * 52
        starttime = utctime - timedelta(weeks=number)
    elif window.endswith('w'):
        starttime = utctime - timedelta(weeks=number)
    elif window.endswith('d'):
        starttime = utctime - timedelta(days=number)
    elif window.endswith('h'):
        starttime = utctime - timedelta(hours=number)
    elif window.endswith('m'):
        starttime = utctime - timedelta(minutes=number)
    elif window.endswith('s'):
        starttime = utctime - timedelta(seconds=number)

    return starttime


def readcredsfile():

    try:
        cb = CBCloudAPI(profile='default')
    except Exception as e:
        log.error('Could not load variables from %s file. Error: %s' % e)
        log.info('Script will exit')
        exit()

    return cb


if __name__ == '__main__':

    main()
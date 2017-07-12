import json
import redis
import subprocess
import threading
import signal
import potsdb
import requests
import time
import os

"""
Global Variables
"""
config = json.load(open("config.json"))
r = redis.StrictRedis(host=config['redis']['address'], port=config['redis']['port'], db=0)
r.flushall()

kDomainsToStore=config['kDomainsToStore']
kIpsToStore=config['kIpsToStore']

qtypes_dict = {'32769': 'DLV', '32768': 'TA', '56': 'NINFO', '51': 'NSEC3PARAM', '45': 'IPSECKEY', '43': 'DS',
                   '60': 'CDNSKEY', '61': 'CDNSKEY', '62': 'CSYNC', '49': 'DHCID', '252': 'AXFR', '253': 'MAILB',
                   '250': 'TSIG', '251': 'IXFR', '256': 'URI', '257': 'CAA', '254': 'MAILA', '255': '*', '24': 'SIG',
                   '25': 'KEY', '26': 'PX', '27': 'GPOS', '20': 'ISDN', '21': 'RT', '22': 'NSAP', '23': 'NSAP-PTR',
                   '46': 'RRSIG', '249': 'TKEY', '44': 'SSHFP', '48': 'DNSKEY', '42': 'APL', '29': 'LOC', '40': 'SINK',
                   '41': 'OPT', '1': 'A', '3': 'MD', '2': 'NS', '5': 'CNAME', '4': 'MF', '7': 'MB', '6': 'SOA',
                   '9': 'MR', '8': 'MG', '59': 'CDS', '52': 'TLSA', '28': 'AAAA', '13': 'HINFO', '99': 'SPF',
                   '47': 'NSEC', '108': 'EUI48', '38': 'A6', '17': 'RP', '102': 'GID', '103': 'UNSPEC', '100': 'UINFO',
                   '101': 'UID', '106': 'L64', '107': 'LP', '104': 'NID', '105': 'L32', '11': 'WKS', '10': 'NULL',
                   '39': 'DNAME', '12': 'PTR', '15': 'MX', '58': 'TALINK', '14': 'MINFO', '16': 'TXT', '33': 'SRV',
                   '32': 'NIMLOC', '31': 'EID', '30': 'NXT', '37': 'CERT', '36': 'KX', '35': 'NAPTR', '34': 'ATMA',
                   '19': 'X25', '55': 'HIP', '109': 'EUI64', '18': 'AFSDB', '57': 'RKEY', '50': 'NSEC3'}

topKDomainsQuery = "http://" + config['openTSDB']['address'] + ":" + config['openTSDB']['port'] \
                   + "/api/query/gexp?start=" + config['topKDomainsQuery']['start'] + "-ago&end=" \
                   + config['topKDomainsQuery']['end'] + "-ago&exp=highestMax(sum:" \
                   + config['topKDomainsQuery']['subsample'] + "-sum-none:Domains{domain=*}," \
                   + str(config['topKDomainsQuery']['k']) + ")"

topKClientsQuery = "http://" + config['openTSDB']['address'] + ":" + config['openTSDB']['port'] \
                   + "/api/query/gexp?start=" + config['topKClientsQuery']['start'] + "-ago&end=" \
                   + config['topKClientsQuery']['end'] + "-ago&exp=highestMax(sum:" \
                   + config['topKClientsQuery']['subsample'] + "-sum-none:Clients{client=*}," \
                   + str(config['topKClientsQuery']['k']) + ")"

topQueryTimeout = config["topQueryTimeout"]

dropCachesQuery = "http://" + config["openTSDB"]["address"] + ":" + config["openTSDB"]["port"] + "/api/dropcaches"

topListsRefreshingTime = config["topListsRefreshingTime"]



"""
Query and Timeout
"""
class TimeOutException(Exception):
    def __init__(self, message):
        super(TimeOutException, self).__init__(message)


def handler(signum, frame):
   raise TimeOutException("Timeout!")

signal.signal(signal.SIGALRM, handler)


def http_query(query):
   return requests.get(query)



def hex2ip(hex_ip: str) -> str:
    """
    Transforms an IP address from hexadecimal to human-readable format
    :param hex_ip: IP address in hexadecimal form (IPv4) and in human-readable (IPv6)
    :return: human-readable form of an IP address (IPv4 and IPv6)
    """
    if ":" in hex_ip:  # Assume IPV6
        return hex_ip

    return ".".join([str(int(hex_ip[i:i + 2], 16)) for i in range(0, 8, 2)])


class Listener(threading.Thread):
    def __init__(self, r, channels):
        threading.Thread.__init__(self)
        self.redis = r
        self.pubsub = self.redis.pubsub()
        self.pubsub.subscribe(channels)

    def run(self):
        for item in self.pubsub.listen():
            if item['type'] == 'message':
                self.work(json.loads(str(item['data'], "utf-8")))
            elif item['data'] == "KILL":
                self.pubsub.unsubscribe()
                print(self, "unsubscribed and finished")
                break
            elif item['type'] == 'subscribe':
                print(self, "subscribed")



"""
PubSub threads
"""
class AnswerPerSecondListener(Listener):
    def work(self, item):
        #(Metric name, value, tags ...)
        metrics.send('AnswersPerSecond', item['data'], timestamp= item["timeStamp"], serverId = item['serverId'])


class QueriesPerSecondListener(Listener):
    def work(self, item):
        #(Metric name, value, tags ...)
        metrics.send('QueriesPerSecond', item['data'], timestamp= item["timeStamp"], serverId = item['serverId'])


class QueriesSummaryListener(Listener):
    def work(self, item):
        dict = {'32769': 0, '32768': 0, '56': 0, '51': 0, '45': 0, '43': 0,
                   '60': 0, '61': 0, '62': 0, '49': 0, '252': 0, '253': 0,
                   '250': 0, '251': 0, '256': 0, '257': 0, '254': 0, '255': 0, '24': 0,
                   '25': 0, '26': 0, '27': 0, '20': 0, '21': 0, '22': 0, '23': 0,
                   '46': 0, '249': 0, '44': 0, '48': 0, '42': 0, '29': 0, '40': 0,
                   '41': 0, '1': 0, '3': 0, '2': 0, '5': 0, '4': 0, '7': 0, '6': 0,
                   '9': 0, '8': 0, '59': 0, '52': 0, '28': 0, '13': 0, '99': 0,
                   '47': 0, '108': 0, '38': 0, '17': 0, '102': 0, '103': 0, '100': 0,
                   '101': 0, '106': 0, '107': 0, '104': 0, '105': 0, '11': 0, '10': 0,
                   '39': 0, '12': 0, '15': 0, '58': 0, '14': 0, '16': 0, '33': 0,
                   '32': 0, '31': 0, '30': 0, '37': 0, '36': 0, '35': 0, '34': 0,
                   '19': 0, '55': 0, '109': 0, '18': 0, '57': 0, '50': 0}

        #Get TopIps and Record Types
        topIps = []
        for element in item['data']:
            ipQueries = 0
            keys = list(element['queries'].keys())
            values = list(element['queries'].values())
            for i in range(0,len(values)):
                dict[keys[i]] += len(values[i])
                ipQueries += len(values[i])
            if (len(topIps) < kIpsToStore):
                topIps.append([element['ip'], ipQueries])
                topIps.sort(key=lambda x: x[1])
            else:
                i = 0
                while(i < kIpsToStore):
                    if (ipQueries >= topIps[i][1]):
                        if (i == kIpsToStore-1):
                            topIps[i] = [element['ip'], ipQueries]
                        else:
                            topIps[i] = topIps[i+1]
                    else:
                        if (i != 0):
                            topIps[i-1] = [element['ip'], ipQueries]
                        break
                    i += 1

        #Send TopIps
        for element in topIps:
            ip = hex2ip(element[0])

            #(Metric name, value, tags ...)
            metrics.send('Clients', element[1], timestamp= item["timeStamp"], serverId = item["serverId"], client = ip)

        #Send Record Types
        for key in sorted(dict.keys()):

            #(Metric name, value, tags ...)
            metrics.send('RecordTypesPerSecond', dict[key], timestamp= item["timeStamp"], serverId = item["serverId"], instance = qtypes_dict[key])


class TopKListener(Listener):
    def work(self, item):
        print(item)


class TopKWithIPListener(Listener):
    def work(self, item):
        dict = item["data"]

        #Get TopDomains
        countdict = dict.copy()
        for element in countdict:
            countdict[element] = len(countdict[element])
        topk_keys = sorted(countdict, key = countdict.get, reverse = True)[:kDomainsToStore]
        for key in topk_keys:
            for value in set(dict[key]):

                #(Metric name, value, tags ...)
                metrics.send('Domains', dict[key].count(value), timestamp= item["timeStamp"], domain = key, serverId = item["serverId"])



"""
Main
"""
if __name__ == "__main__":
    metrics = potsdb.Client(config["openTSDB"]["address"], config["openTSDB"]["port"])

    answersPerSecond = AnswerPerSecondListener(r, ['AnswersPerSecond'])
    answersPerSecond.start()

    queriesPerSecond = QueriesPerSecondListener(r, ['QueriesPerSecond'])
    queriesPerSecond.start()

    queriesSummary = QueriesSummaryListener(r, ['QueriesSummary'])
    queriesSummary.start()

    topK = TopKListener(r, ['TopK'])
    ##topK.start() #Not used channel

    topKWithIP = TopKWithIPListener(r, ['TopKWithIP'])
    topKWithIP.start()


    """
    Update Top Lists for Grafana TopKDashboard
    """
    while(True):

        #Update TopDomains' List
        print("Starting TopDomains query")
        successDomain = 0
        signal.alarm(topQueryTimeout)
        try:
            reqDomain = http_query(topKDomainsQuery)
            signal.alarm(0)
            print("Success")
            jDomain = reqDomain.json()
            subprocess.call(["/home/cate/OpenTSDB/opentsdb/build/tsdb","uid","delete","metrics","TopKDomains"])
            successDomain = 1
        except TimeOutException:
            print("HTTP Query takes too long")

        #Update TopClients' List
        print("Starting TopClients query")
        successClient = 0
        signal.alarm(topQueryTimeout)
        try:
            reqClient = http_query(topKClientsQuery)
            signal.alarm(0)
            print("Success")
            jClient = reqClient.json()
            subprocess.call(["/home/cate/OpenTSDB/opentsdb/build/tsdb","uid","delete","metrics","TopKClients"])
            successClient = 1
        except TimeOutException:
            print("HTTP Query takes too long")

        if(successDomain == 1 or successClient == 1):
            requests.get(dropCachesQuery)
            if (successDomain == 1):
                i=1
                print("TopDomains:")
                for element in jDomain:
                    print(str(i) + ": " + element['tags']['domain'])

                    #(Metric name, value, tags ...)
                    metrics.send('TopKDomains', i, domain = element['tags']['domain'])

                    i+=1
            if (successClient == 1):
                i=1
                print("TopClients:")
                for element in jClient:
                    print(str(i) + ": " + element['tags']['client'])

                    #(Metric name, value, tags ...)
                    metrics.send('TopKClients', i, client = element['tags']['client'])

                    i+=1
        time.sleep(topListsRefreshingTime)
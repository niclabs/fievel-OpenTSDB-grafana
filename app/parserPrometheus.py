import json
import redis
import subprocess
import threading
import os

"""
Global Variables
"""
config = json.load(open("config.json"))
r = redis.StrictRedis(host=config['redis']['address'], port=config['redis']['port'], db=0)
r.flushall()

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

#Transforms an IP address from hexadecimal to human-readable format
def hex2ip(hex_ip: str) -> str:
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
        subprocess.call(["./SendAnswersPerSecondMetric", item['serverId'], str(item['data']), str(item['timeStamp']) + "000"], stderr=open(os.devnull, 'wb'))


class QueriesPerSecondListener(Listener):
    def work(self, item):
        subprocess.call(["./SendQueriesPerSecondMetric", item['serverId'], str(item['data']), str(item['timeStamp']) + "000"], stderr=open(os.devnull, 'wb'))


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

        #Get Record Types
        for element in item['data']:
            keys = list(element['queries'].keys())
            values = list(element['queries'].values())
            for i in range(0,len(values)):
                dict[keys[i]] += len(values[i])

        sh = ["./SendRecordTypesPerSecondMetric", item['serverId'], str(item['timeStamp']) + '000']
        for key in sorted(dict.keys()):
            sh.append(str(dict[key]))

        #Send Record Types
        subprocess.call(sh, stderr=open(os.devnull, 'wb'))


class TopKListener(Listener):
    def work(self, item):
        print(item)


class TopKWithIPListener(Listener):
    def work(self, item):
        print(item)



"""
Main
"""
if __name__ == "__main__":
    answersPerSecond = AnswerPerSecondListener(r, ['AnswersPerSecond'])
    answersPerSecond.start()

    queriesPerSecond = QueriesPerSecondListener(r, ['QueriesPerSecond'])
    queriesPerSecond.start()

    queriesSummary = QueriesSummaryListener(r, ['QueriesSummary'])
    queriesSummary.start()

    topK = TopKListener(r, ['TopK'])
    ##topK.start() #Not used channel

    topKWithIP = TopKWithIPListener(r, ['TopKWithIP'])
    ##topKWithIP.start() #Not used channel
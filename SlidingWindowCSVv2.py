import csv
from datetime import datetime, timedelta
from xmlrpc.client import Boolean

import isAccessHit
from scapy.supersocket import tpacket_auxdata

#Program to parse through data using a sliding door algorithm

    #!  rows is a list where each element is a row in a csv file         !
rows = []
#DnsDetectionTest2.csv
fileName = "altered_source_plaindata2.csv"

#value for checking DNS tunneling ttl
timebound = 180;
dns_lines = []

#converts string into formated time value
def parse_time(time):
    return datetime.strptime(time, '%H:%M:%S')

#open file once and copy contents to an array
#can use any csv file as it filters during execution but must have time value in first column
def read_file(unreadFileName):
    with open(unreadFileName) as file:
        reader = csv.reader(file)
        header = next(reader)

        for row in reader:
            rows.append(row)

    #return rows

#checks if there is a ttl and if ttl is lower than acceptable value
#returns true is ttl is lower than accepted bound
def invalid_ttl_check(given_ttl, timecheck):

    ttl = int(given_ttl)
    if ttl <= timebound:
        return True
    else:
            return False

#returns a dict of only one key value
def find_largest(dict):
    newdict = {}

    key = max(dict, key=dict.get)
    value = dict[key]

    newdict[key] = value

    return newdict


# sliding window algorithm
# Uses the time value from file to define the size of the window
def sliding_window(size, increase):
    read_file(fileName)
    results = []
    dns_counter = 0

    startingTime = parse_time(rows[0][0])
    endingTime = parse_time(rows[-1][0])

    #dict for holding rows that hit 2 of 3 flags
    # {qname : row}
    Access_Misses = {}

    #Holds Access Miss Count for each ip
    # {ip : int}
    Access_Miss_count = {}

    #holds the expected time of repeated queries. items here will only have small ttl
    # at an expected time there could be a number of qnames to look for
    # {expected_time (time obj) : qname[]}
    expected_repeats = {}

    # Holds rows that are waiting for a response
    # {transaction ID : row}
    Pending_Transactions = {}

    while startingTime < endingTime:
        # defining the window size

        windowStartingTime = startingTime
        windowEndingTime = windowStartingTime + timedelta(seconds=size)
        print(windowStartingTime, " | ", windowEndingTime)



        #inside the window
        for i in range(len(rows)):

            row = rows[i]

            ip = row[2]
            #print(row)

            if windowStartingTime <= parse_time(row[0]) < windowEndingTime:
                timestamp = row[0]
                response_flag = row[1]
                qname = row[4]
                type = row[5]
                transactionID = row[7]
                #row is a qeury
                if response_flag == '0':

                    if timestamp in expected_repeats.keys():
                        if qname in expected_repeats[timestamp]:
                            expected_repeats[timestamp].pop(qname)
                            #reduce flags

                    ip = row[2]

                    access_hit = isAccessHit.isAccessHit(qname)
                    if not access_hit:
                        flag = False
                        #add ip into AMC or add 1
                        if ip not in Access_Miss_count:
                            Access_Miss_count[ip] = 1
                        else:
                            Access_Miss_count[ip] += 1

                        if len(qname) > 70 or not (type == "A" or type == "AAAA"):

                            Access_Misses[qname] = row
                            Pending_Transactions[transactionID] = row
                            print("PEnding transaction")
                            print(transactionID , " " ,Pending_Transactions[transactionID])



                #row is a response
                else:
                    if transactionID in Pending_Transactions.keys():
                        ttl = row[6]

                        if invalid_ttl_check(ttl, timebound):
                            time = int(ttl)
                            seconds = timedelta(seconds=time)
                            expected_time = parse_time(timestamp) + seconds
                            #if expectedtiem  does exists
                            if expected_time not in expected_repeats.keys():
                                qnames = [qname]
                                expected_repeats[expected_time] = (qnames)
                            #expected time does exist
                            else:
                                expected_repeats[expected_time].append(qname)
                        print("Popping ", transactionID, " from Pending transactions ", Pending_Transactions[transactionID], " ", row)
                        Pending_Transactions.pop(transactionID)


        startingTime = windowEndingTime + timedelta(seconds=1)
    print("ALL ACCESS MISSES AND HIT ONE FLAG")
    for x in Access_Misses.keys():
        print(x, " | ", Access_Misses[x])
    print("ALL EXPECTED REPEATS")
    for x in expected_repeats.keys():
        print(x, " | ", expected_repeats[x])
    print("ALL PENDING RESPONSES")
    print(Pending_Transactions)
    for x in Pending_Transactions.keys():
        print(x, " | ", Pending_Transactions[x])
    print("ACCESS MISS COUNTS")
    for x in Access_Miss_count:
        print(x, " | ", Access_Miss_count[x])

   # wreit(results, dns_lines)

    #return

#increase is the increase in traffic to chekc for, size is the size of the window
sliding_window(30, 30)

def archive():
    qname = row[4]
    response_flag = row[1]

    # check flag if 0 / a query
    if response_flag == '0':
        transactionID = row[5]
        if ip in traffic:
            traffic[ip] += 1
            # print("IP: ", ip , " traffic: ",traffic[ip])
        else:
            traffic[ip] = 1
            ip_invald_ttl[ip] = 1

        if ip not in no_response:
            no_response[ip] = 0

        # checking if qname is repeated
        # if it is removes the row from flagged rows

        if qname in AccessMissList.keys():
            AccessMissList.pop(qname)
            print("popped: ", qname)

        # check if qname is not in accesslist
        # if not then access miss
        access_hit = isAccessHit.isAccessHit(qname)

        if not access_hit:
            if len(qname) > 70:
                if qname not in AccessMissList:
                    print("qname: ", qname, " length: ", len(qname))
                    AccessMissList[qname] = row

            transactionlist.append(transactionID)

            # keeps track of access miss counts
            if ip not in machines_AMC:
                machines_AMC[ip] = 1

                if traffic[ip] > initial_base[ip]:
                    ip_scores[ip] *= 2

            else:
                machines_AMC[ip] += 1

    # row is a response
    else:
        if not isAccessHit.isAccessHit(qname):
            ip = row[3]
            # check if query query was responded to

            if len(row) > 6:
                transactionID = row[6]
                if transactionID in transactionlist:
                    no_response[ip] -= 1

                if invalid_ttl_check(row, timebound):

                    AccessMissList[qname] = row

                    if ip not in ip_invald_ttl:
                        ip_invald_ttl[ip] = 1
                    else:
                        ip_invald_ttl[ip] += 1

        if machines_AMC:
            largest = find_largest(machines_AMC)
        else:
            print("no access misses")

        for x in no_response.keys():
            print(machines_AMC.keys())
            no_response[x] += largest[x]
            print("no response number", no_response[x])
            ip_scores[x] *= no_response[x]

        no_response_score = 0
        for x in AccessMissList.keys():
            row = AccessMissList[x]
            ip = row[2]
            ip_scores[ip] += 2

        for x in largest.keys():
            ip_scores[x] += largest[x]
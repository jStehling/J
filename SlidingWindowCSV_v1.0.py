import csv
from datetime import datetime, timedelta
from xmlrpc.client import Boolean

import isAccessHit
from scapy.supersocket import tpacket_auxdata

#Program to parse through data using a sliding door algorithm

    #!  rows is a list where each element is a row in a csv file         !
rows = []
#DnsDetectionTest2.csv
fileName = "personaltraffic.csv"

#value for checking DNS tunneling ttl
timebound = 120;
dns_lines = []

#valid types
valid_types = ["A", "AAAA"]

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

def valid_type(type):
    return type in valid_types

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

    #holds qname and checks that a qname is repeated
    repeats = []

    # Holds rows that are waiting for a response
    # {transaction ID : row}
    Pending_Transactions = {}

    #dict for holding ip and counting how many queries of uncommon types there are
    # {ip : [type, int]
    uncommon_count = {}

    # {ip : row}
    probable_tunneling = {}

    while startingTime < endingTime:
        # defining the window size

        windowStartingTime = startingTime
        windowEndingTime = windowStartingTime + timedelta(seconds=size)
        print(windowStartingTime, " | ", windowEndingTime)



        #inside the window
        for i in range(len(rows)):

            row = rows[i]
            #print(row)


            if windowStartingTime <= parse_time(row[0]) < windowEndingTime:
                timestamp = row[0]
                response_flag = row[1]
                qname = row[4]
                type = row[5]
                transactionID = row[7]
                #row is a qeury
                if response_flag == '0':
                    dns_counter+= 1

                    if qname in repeats:
                        repeats.remove(qname)

                    ip = row[2]

                    access_hit = isAccessHit.isAccessHit(qname)
                    if not access_hit:

                        if qname not in repeats:
                            repeats.append(qname)

                        flag = False
                        #add ip into AMC or add 1
                        if ip not in Access_Miss_count:
                            Access_Miss_count[ip] = 1
                        else:
                            Access_Miss_count[ip] += 1

                        if len(qname) > 70 or not valid_type(type):

                            if not valid_type(type):
                                if ip not in uncommon_count.keys():
                                    uncommon_count[ip] = 1
                                else:
                                    uncommon_count[ip] += 1
                                    print(ip, " | ", uncommon_count[ip])

                            Access_Misses[qname] = row
                            Pending_Transactions[transactionID] = row

                #row is a response
                else:
                    if transactionID in Pending_Transactions.keys():
                        Pending_Transactions.pop(transactionID)

            if ip in uncommon_count.keys():
                if uncommon_count[ip] > 4000000 and Access_Miss_count[ip] > 20:
                    print("TUNNELING at: ", ip)
                    print("CHECKED FLAGGED ROWS")
                    print("ALL ACCESS MISSES AND HIT ONE FLAG")
                    for x in Access_Misses.keys():
                        print(x, " | ", Access_Misses[x])
                    print("----------------------------")
                    print("ACCESS MISS COUNTS")
                    for x in Access_Miss_count:
                        print(x, " | ", Access_Miss_count[x])
                    print("----------------------------")
                    print("ALL PENDING RESPONSES/NO RESPONSES")
                    for x in Pending_Transactions.keys():
                        print(x, " | ", Pending_Transactions[x])
                    print("----------------------------")
                    print("UNCOMMON QUERY TYPE COUNT")
                    for x in uncommon_count.keys():
                        print(x, " | ", uncommon_count[x])
                    exit()

        startingTime = windowEndingTime + timedelta(seconds=1)
        print(startingTime, " | ", windowEndingTime)

    for ip in uncommon_count.keys():
        if uncommon_count[ip] > 40 and Access_Miss_count[ip] > 20:
            print("TUNNELING at: ", ip)
            print("CHECKED FLAGGED ROWS")
            print("ALL ACCESS MISSES AND HIT ONE FLAG")
            for x in Access_Misses.keys():
                print(x, " | ", Access_Misses[x])
            print("----------------------------")
            print("ACCESS MISS COUNTS")
            for x in Access_Miss_count:
                print(x, " | ", Access_Miss_count[x])
            print("----------------------------")
            print("ALL PENDING RESPONSES/NO RESPONSES")
            for x in Pending_Transactions.keys():
                print(x, " | ", Pending_Transactions[x])
            print("----------------------------")
            print("UNCOMMON QUERY TYPE COUNT")
            for x in uncommon_count.keys():
                print(x, " | ", uncommon_count[x])
    #return

#increase is the increase in traffic to chekc for, size is the size of the window
sliding_window(30, 30)

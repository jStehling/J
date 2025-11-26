import csv
from datetime import datetime, timedelta
import isAccessHit
#Program to parse through data using a sliding door algorithm

    #!  rows is a list where each element is a row in a csv file         !
rows = []
fileName = "DnsDetectionTest2.csv"

#value for checking DNS tunneling ttl
timebound = 180;
dns_lines = []

#converts string into formated time value
def parse_time(time):
    return datetime.strptime(time, '%H:%M:%S')

def wreit(results, dns_lines):
    with open("results.csv", mode='w', newline='') as file:

        file.write("Probable DNS tunneling: (Logging purposes)")
        for row in dns_lines:
            file.write(row)

        file.write("\n")
        file.write("distinct IP addresses")
        for row in results:
            file.write(row)

#open file once and copy contents to an array
#can use any csv file as it filters during execution but must have time value in first column
def read_file(unreadFileName):
    with open(unreadFileName) as file:
        reader = csv.reader(file)
        header = next(reader)

        for row in reader:
            rows.append(row)

    #!  sorting rows would make things harder. in pcap files,             !
    #!  responses, which we need to check if its an access miss,          !
    #!  are always right after the request regardless of when it arrives. !
    #!  we could just find the response but thats a pain                  !
    #rows.sort(key=lambda time: parse_time(time[0]))

    #return rows

#checks if there is a ttl and if ttl is lower than acceptable value
#returns true is ttl is lower than accepted bound
def invalid_ttl_check(row, timecheck):

    ttl = int(row[5])
    if ttl <= timebound:
        return True
    else:
            return False

def volume_traffic_monitor(size):
    read_file(fileName)
    currenttime = parse_time(rows[0][0])
    endingtime = currenttime + timedelta(minutes=1)

    dict = {}

    counter = 0
    while currenttime < endingtime:
        row = rows[counter]

        if row[1] == '0':
            if row[2] not in dict:
                dict[row[2]] = 1
            else:
                dict[row[2]] += 1

        counter += 1
        currenttime = parse_time(rows[counter][0])
    return dict

#returns a dict of only one key value
def find_largest(dict):
    newdict = {}

    key = max(dict, key=dict.get)
    value = dict[key]

    dict.pop(key)

    newdict[key] = value

    return newdict


# sliding window algorithm
# Uses the time value from file to define the size of the window
def sliding_window(size, increase):
    read_file(fileName)
    results = []
    dns_counter = 0
    #!
    startingTime = parse_time(rows[0][0])
    endingTime = parse_time(rows[-1][0])
    line_tracker = 1

    # dictionary for initial monitoring traffic
    initial_base = volume_traffic_monitor(size)

    #dictionary for keeping track of ip and queries without responses
    no_response = {}
    no_respone_row = []

    # Dict for calculating scores for IPs
    ip_scores = {}

    #dict for holding largest IPs
    largest = {}

    while startingTime < endingTime:
        #defining the window size
        startingMinute = startingTime.minute
        startingHour = startingTime.hour
        windowStartingTime = parse_time(f"{startingHour:02}:{startingMinute:02}:00")
        windowEndingTime = windowStartingTime + timedelta(minutes=size)

        # access misscounts for current window. reset every window
        machines_AMC = {}



        # traffic count for every window, resets every window
        traffic = {}
        temprow = []

        #dict for monitoring invalid TTL count
        ip_invald_ttl = {}

        #inside the window
        for i in range(len(rows)):
            row = rows[i]

            ip = row[2]

            if ip not in ip_scores:
                ip_scores[ip] = 1

            if windowStartingTime <= parse_time(row[0]) < windowEndingTime:\

                #check flag if 0 / a query
                if row[1] == '0':
                    temprow = row.copy()


                    #checks ip and adds it to traffic counter
                    if ip in traffic:
                        traffic[ip] += 1
                       # print("IP: ", ip , " traffic: ",traffic[ip])
                    else:
                        traffic[ip] = 1
                        ip_invald_ttl[ip] = 1

                       # print("IP: ", ip, " traffic: ", traffic[ip])


                    #check if qname is not in accesslist
                    #if not then access miss
                    if not isAccessHit.isAccessHit(row[4]):

                        # if not in accesslist check its TTL
                        nextrow = rows[i+1]

                        #checks if the next row is a response to query
                        #if a response then cheks ttl
                        #if no response WITHIN GIVEN WINDOW added to dns_lines
                        if nextrow[1] == '0':
                            if ip in no_response:
                                no_response[ip] += 1
                                no_respone_row.append(row)

                                machines_AMC[ip] += 1
                            else:
                                no_response[ip] = 1
                                no_respone_row.append(row)
                                machines_AMC[ip] = 1

                            if row not in dns_lines:
                                dns_lines.append(row)
                            #print("no response: " ,ip, " ", no_response[ip])
                            #print(row)
                        else:
                            #   if ttl is lower than certain value its a positive
                            #   (ACCESS MISS COUNT)
                            if  len(nextrow) > 5 and invalid_ttl_check(nextrow, timebound):

                                source_machine = nextrow[3]

                                if source_machine not in ip_invald_ttl:
                                    ip_invald_ttl[source_machine] = 1
                                else:
                                    ip_invald_ttl[source_machine] += 1

                                if source_machine in no_response.keys():
                                    if nextrow not in dns_lines:
                                        dns_lines.append(row)
                                        dns_lines.append(nextrow)
                                    dns_counter += 1

                                    if source_machine not in machines_AMC:
                                        machines_AMC[source_machine] = 1

                                        #print("AMC detected at: ", source_machine, " AMC count: ",machines_AMC[source_machine])
                                    else:
                                        machines_AMC[source_machine] += 1

                                    #print("AMC detected at: ", source_machine, " AMC count: ",machines_AMC[source_machine])

                    # if in accesslist then its benign

        #get the traffic volume for ips with most AMC
        if machines_AMC:
            #192.168.68.1 is the AP, dont know why its making queries
            if '192.168.68.1' in machines_AMC.keys():
                machines_AMC.pop('192.168.68.1')

            #gets the IPs with the largest amount of AMC and loops through them
            #check that ip is in no_response, and ip has an increase in traffic
            #checls key is in dns_lines as source or destination, and appends it
            #to results if not already there
            largest = find_largest(machines_AMC)

            #following code is more for high throughput tunneling
            if 1 == 2:
                for key in largest.keys():
                    #print(key, " AMC: ", largest[key], " traffic: ", traffic[key], " previous traffic: ", initial_base[key])
                    if key in no_response.keys():
                        if traffic[key] > initial_base[key] + increase:
                            for x in range(len(dns_lines)):
                                tempo = dns_lines[x]
                                if key == tempo[2] or key == tempo[3]:
                                    if key not in results:
                                        results.append(key)

            ip_scores.pop('192.168.68.1')

            for key in ip_scores.keys():
                multip = 1

                if key in no_response.keys():
                    ip_scores[key] = ip_scores[key] + 3

                if key in ip_invald_ttl.keys():
                    ip_scores[key] = ip_scores[key] + 3
                    multip += 1

                if key in largest.keys():
                    ip_scores[key] = ip_scores[key] + 2
                    multip += 1

                if traffic[key] > initial_base[key] + increase:
                    ip_scores[key] = ip_scores[key] + 1
                    multip += 1

                ip_scores[key] = ip_scores[key] * multip


        print("new window")
        startingTime = windowEndingTime
        #current traffic becomes old traffic
        initial_base = traffic.copy()

    print("flagged dns tunneling lines")
    for x in dns_lines:
        print(x)
    print("infected computer/s")
    for x in ip_scores.keys():

        if ip_scores[x] >= 40:
            print(x)
            print("IP DNST score: " , ip_scores[x])
            if x in largest.keys():
                print("AMC value: ", largest[x])
            if x in no_response.keys():
                print("no response count: ", no_response[x])
            if x in ip_invald_ttl.keys():
                print("TTL invald count: ", ip_invald_ttl[x])


   # wreit(results, dns_lines)

    #return

#increase is the increase in traffic to chekc for, size is the size of the window
sliding_window(1, 10)




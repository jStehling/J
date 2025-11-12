from _datetime import timedelta

import matplotlib.pyplot as plt

import csv
import datetime

# parameters for displaying data
volume = {}
volumes = []
times = []
timeshift = timedelta(hours=0, minutes=15, seconds=0)

#dor altering sources
iplist = []
ip_preffix = "192.168.68."
ip_suffix = 100
metadata = ["timestamp", "flag", "source", "destination", "qname", "ttl"]

#for x in range(18):
   # ip = ip_preffix + str(ip_suffix)
   # iplist.append(ip)
   # ip_suffix += 1

def alter_source_dataset(filepath, iplist, metadata):
    # !!!!!
    # CHANGE WRITER FILE NAME
    # !!!!!
    listlen = len(iplist)
    queue_index = 0

    with open(filepath ,mode='r') as file, open('altered_source_plaindata2.csv', mode='w', newline='') as newfile:
        reader = csv.reader(file, delimiter=',')
        next(reader)
        writer = csv.writer(newfile, delimiter=',')
        writer.writerow(metadata)

        for line in reader:
            row = []
            #if line is a request
            #change its source address
            #timestamp | flag | source | destination | qname  | TTL
            #    0     |   1  |   2    |      3      |   4    |
            if line[1] == '0':
                row.append(line[0])
                row.append(line[1])
                row.append(iplist[queue_index])
                row.append(line[3])
                row.append(line[4])
            else:
                row.append(line[0])
                row.append(line[1])
                row.append(line[2])
                row.append(iplist[queue_index])
                row.append(line[4])
                if len(line) > 5:
                    row.append(line[5])
            writer.writerow(row)

            if reader.line_num % 2 == 1:
                queue_index = (queue_index + 1) % listlen
                #change the nextlines destination to iplist[queue_index]
                #update queue_index

    file.close()
    newfile.close()




def create_dataset(filepath):
    with open(filepath ,mode='r') as file:
        csvFile = csv.reader(file, delimiter=',')
        next(csvFile)

        for line in csvFile:

            if line[1] == '0':

                str1 = line[0]
                dt = datetime.datetime.strptime(str1, '%H:%M:%S')
                timestamp = dt.strftime('%H:%M')
                check = int(str(timestamp)[3:])
                if check % 2 == 0:
                    if timestamp not in times:
                        times.append(timestamp)
                        volume[timestamp] = 0

                    volume[timestamp] += 1



def create_graph(volume, times):
    for x in volume:
        volumes.append(volume[x])

    print(times)
    print(volumes)
    plt.plot(times, volumes)
    plt.xlabel("Times")
    plt.ylabel("Volume of traffic")
    #plt.figure(figsize=(20,20))
    plt.show()

def checkstuff(filepath):
    counter = 0
    with open(filepath ,mode='r') as file:
        csvFile = csv.reader(file, delimiter=',')
        line = next(csvFile)
        st1r = ""
        for x in range(len(line)):
            st1r = str(x)+ ": " + line[x]
            print(st1r)


#checkstuff("plain2.csv")
#create_dataset("altered_frequency_plaindata2.csv")
#create_graph(volume, times)


alter_source_dataset("plain2.csv", iplist, metadata)
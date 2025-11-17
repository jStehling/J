import csv
from datetime import datetime, timedelta

#Program to parse through data using a sliding door algorithm

rows = []
fileName = "plain2.csv"

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

    rows.sort(key=lambda time: parse_time(time[0]))
    return rows

# sliding window algorithm
# Uses the time value from file to define the size of the window
def sliding_window():
    read_file(fileName)
    startingTime = parse_time(rows[0][0])
    endingTime = parse_time(rows[-1][0])

    while startingTime < endingTime:
        #defining the window size
        startingMinute = startingTime.minute
        startingHour = startingTime.hour
        windowStartingTime = parse_time(f"{startingHour:02}:{startingMinute:02}:00")
        windowEndingTime = windowStartingTime + timedelta(minutes=1)

        #inside the window
        for row in rows:
            if windowStartingTime <= parse_time(row[0]) < windowEndingTime:
                print(row)
        print()
        print()
        print()
        print("New Window")
        startingTime = windowEndingTime

    return


sliding_window()


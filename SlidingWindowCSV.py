import csv
from datetime import datetime, timedelta

#Program to parse through data using a sliding door algorithm

#converts string into formated time value
def parse_time(time):
    return datetime.strptime(time, '%H:%M:%S')

rows = []

#open file once and copy contents to an array
#can use any csv file as it filters during execution but must have time value in first column
with open("plain2.csv") as file:
    reader = csv.reader(file)
    header = next(reader)

    for row in reader:
        rows.append(row)

rows.sort(key=lambda time: parse_time(time[0]))

print(rows[0])

#sliding window algorithm
#Uses the time value from file to define the size of the window
startingTime = parse_time(rows[0][0])
endingTime = parse_time(rows[-1][0])

while startingTime < endingTime:
    startingMinute = startingTime.minute
    startingHour = startingTime.hour
    windowStartingTime = parse_time(f"{startingHour:02}:{startingMinute:02}:00")
    windowEndingTime = windowStartingTime + timedelta(minutes=1)

    for row in rows:
        if windowStartingTime <= parse_time(row[0]) < windowEndingTime:
            lastRow = rows.index(row)
            print(row)

    print()
    print()
    print()
    print("New Window")
    startingTime = windowEndingTime
















import tldextract
import csv
## Global variable containing access list. Will be "updated" every run
## Helper functions
# Gets the domains from the access list to compare
def getAccessList() -> None:
        with open('personalAccessList.txt') as f:
            return [line.strip() for line in f if line.strip()]
            


# Returns base domain (i.e google.com) as a string, even when given subdomains such as (mail.google.com)
# Reference to not get cooked (or skinned and turned into a purse): https://stackoverflow.com/questions/44021846/extract-domain-name-from-url-in-python#:~:text=Use%20tldextract%2C%20which,domain%0A%27cnn%27
def parseDomain(domain: str) -> str:
    extracted: str = tldextract.extract(domain)
    return extracted.domain + "." + extracted.suffix

# Returns True if the domain is in the access list, returns false if not (false = access miss)
def isAccessHit(domain: str, accessList: list) -> bool:
    parsed = parseDomain(domain)
    if parsed in accessList:
         return True
    else: 
         return False

# Main runnable
if __name__ == "__main__":
    accessList = getAccessList()
    with open("altered_source_plaindata2.csv", mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        try:
            next(reader)
        except StopIteration:
            print("Error: CSV file is empty.")
            exit()
            
        QNAME_INDEX = 4  
        FLAG_INDEX = 1

        for line in reader:
            if len(line) > QNAME_INDEX:
                
                if line[FLAG_INDEX] == '0':
                    domain: str = line[QNAME_INDEX].strip()  
                    print(isAccessHit(domain, accessList))

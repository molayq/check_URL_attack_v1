import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time
from urllib.parse import urlparse
import pydnsbl

import requests
import datetime
import whois

def daysScenario(extractedDomainDetails):
    domainCreationDate = extractedDomainDetails.creation_date
    print(domainCreationDate)
    print(datetime.datetime.now())
    s = datetime.datetime.now() - domainCreationDate
    if (s.days < 100):
        print("possible for domain: ", extractedDomainDetails.name)
    else:
        print("not really possible in registered days scenario for domain: ", extractedDomainDetails.name)

def check_attack():
    rootUrl = 'https://oran.ge/3gdsG7h'
    attackRootRequest = requests.get(
        rootUrl,
        allow_redirects=True, verify=False)
    # print(page.url)
    # print(page.status_code)

    pagePossibleRedirect = attackRootRequest.url
    print(urlparse(rootUrl).netloc)
    y = urlparse(rootUrl).netloc
    x = whois.query(y)
    daysScenario(x)
    domain_checker = pydnsbl.DNSBLDomainChecker()
    print(domain_checker.check(y))

    print('##### -> Redirect through a phishing page ->', pagePossibleRedirect)
    justDomain = urlparse(pagePossibleRedirect).netloc

    domain_checker = pydnsbl.DNSBLDomainChecker()
    print(domain_checker.check(justDomain))

    extractedDomainDetails = whois.query(justDomain)

    daysScenario(extractedDomainDetails)

    ####check if the redirect was made
    pageHistory = ''
    print(attackRootRequest.history)
    for response in attackRootRequest.history:
        print('##### -> Before redirect through a phishing page ->', response.url)

        # pageHistory = response.url
        rollOver = '##### -> Pages kept the same.' if pagePossibleRedirect == response.url else '##### -> Redirect was made'
        print(rollOver)


check_attack()

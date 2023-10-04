import sys
from bs4 import BeautifulSoup
import urllib.request
import os

def parse(CVE):
    page = "https://www.cvedetails.com/cve-details.php?t=1&cve_id={}".format(CVE)
    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
    headers = {'User-Agent': user_agent, }
    request = urllib.request.Request(page, None, headers)
    response = urllib.request.urlopen(request)
    data = response.read()
    soup = BeautifulSoup(data, "html.parser")
    cve_info = ""

    #CVE name
    h2 = soup.find("h2", class_="mt-4")
    if h2:
        cve_name = h2.text.split()[-1] + "\n"
    else:
        print("CVE name not found")
    cve_info = cve_name + "\n"

    #Table
    table = soup.find('table', class_='table table-borderless')

    def decode(d):
        r = int(d[:2], 16)
        email = ''.join([chr(int(d[i:i + 2], 16) ^ r) for i in range(2, len(d), 2)])
        return email

    if table:
        rows = table.find_all('tr')
        i = 1
        for row in rows:
            if i%2:
                cve_info += (f"Base Score: {row.find_all('div')[0].text}\n")
                email = row.find_all('a', {'data-cfemail': True})
                for e in email:
                    cve_info += (f"Vendor: {decode(e['data-cfemail'])}\n")
                i += 1
            else:
                res = row.find("div")
                for r in res:
                    if r != "\n":
                        cve_info += (f"{r.text}\n")
                i += 1

    #CWE ID
    cwe = soup.find('li', class_='list-group-item').find("a").text.split()[0]
    cve_info += cwe + "\n----------------------------------------------------------\n"

    file_path = "CVE.txt"
    exist = False

    if os.path.isfile(file_path):
        with open(file_path, "r") as file:
            for line in file:
                if cve_name in line:
                    print("Запись не добавлена в файл, так как уже существует")
                    exist = True
                    break
        if not exist:
            with open(file_path, "a") as file:
                file.write(cve_info)
    else:
        with open(file_path, "a") as file:
            file.write(cve_info)

    return cve_info

# Running
CVE = sys.argv[1]
result = parse(CVE)
import json
import re
from selenium import webdriver
from selenium.webdriver.common.by import By
import time
import sys

with open('output.json', 'r') as file:
    data = json.load(file)

cve_results = []
options = webdriver.ChromeOptions()
options.add_argument("--window-size=1920,1080")
options.add_argument("--headless")
driver = webdriver.Chrome(options=options)
firstime=True
data = data[0:5]

for entry in data:
    link = entry['link']
    
    # Visit the link
    driver.get(link)
    if firstime:
        firstime = False
        time.sleep(3)
    time.sleep(2)
    try:
        cve_pattern = re.compile(r'CVE-\d{4}-\d+')
        cve_match = cve_pattern.search(driver.page_source)
        
        if cve_match:
            cve_id = cve_match.group()
            print("CVE ID FOUND:", cve_id)
            sys.stdout.flush()
        else:
            print("No CVE ID found...skipping")
            sys.stdout.flush()
            continue
        
    except Exception as e:
        print("Error occurred while extracting CVE ID:", str(e))
        continue

    cve_results.append({
        'cveid': cve_id,
        'program': entry['link']
    })

driver.quit()

output_json = json.dumps(cve_results, indent=4)

print(output_json)

with open('cve_output.json', 'w') as json_file:
    json_file.write(output_json)


#

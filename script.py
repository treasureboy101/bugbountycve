import time
import csv
import json
from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By

hacktivity_url = 'https://hackerone.com/hacktivity/overview'
page_loading_timeout = 10


def extract_reports(raw_reports):
    reports = []
    for raw_report in raw_reports:
        html = raw_report.get_attribute('href')
        try:
            index = html.index('/reports/')
        except ValueError:
            continue
        link = 'hackerone.com'
        for i in range(index, len(html)):
            if html[i] == '"':
                break
            else:
                link += html[i]
        report = {
            'program': '',
            'title': '',
            'link': link,
            'upvotes': 0,
            'bounty': 0.,
            'vuln_type': ''
        }
        reports.append(report)

    return reports


def fetch():
    options = ChromeOptions()
    options.add_argument('no-sandbox')
    options.add_argument('headless')
    driver = Chrome(options=options)

    reports = []
    with open('data.csv', 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            reports.append(dict(row))
    first_report_link = reports[0]['link']
    try:
        with open('cve_output.json', 'r') as file:
            existing_cve_data = json.load(file)
            existing_links = set(entry['link'] for entry in existing_cve_data)
    except FileNotFoundError:
        existing_links = set()
    driver.get(hacktivity_url)
    time.sleep(page_loading_timeout)

    page = 0
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
    next_page_button = driver.find_element(
        By.CSS_SELECTOR, 'button[data-testid=\'hacktivity-next-button\']')
    new_reports = []
    while True:
        raw_reports = driver.find_elements(By.CLASS_NAME, 'routerlink')
        new_reports += extract_reports(raw_reports)
        found = False
        for i in range(len(new_reports)):
            if new_reports[i]['link'] == first_report_link:
                reports = new_reports[:i] + reports
                found = True
                break
        if found:
            break

        page += 1
        print('Page:', page)
        next_page_button.click()
        time.sleep(page_loading_timeout)
        driver.execute_script(
            "window.scrollTo(0, document.body.scrollHeight);")

    driver.close()

    with open('data.csv', 'w', newline='', encoding='utf-8') as file:
        keys = reports[0].keys()
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(reports)

    # Process the fetched data for CVE scraping
    print("JSON file ready")
    data = json.dumps(reports, indent=4)
    data = json.loads(data)
    cve_results = []
    options = ChromeOptions()
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--headless")
    driver = Chrome(options=options)
    firstime = True
    print("starting to scrape")
    i = 0
    for entry in data:
        link = "https://"+entry['link']
        if link in existing_links:
            print(f"{i} Skipping {link} as it has already been processed")
            break
        driver.get(link)
        if firstime:
            firstime = False
            time.sleep(3)
        time.sleep(5)
        try:
            cve_element = driver.find_element(By.CSS_SELECTOR,
                                              '.spec-cve-id-meta-item .metadata-item-value .daisy-link.routerlink')

            cve_id = cve_element.text
            print(f"{i} CVE ID FOUND", cve_id)

        except:
            try:
                cve_element = driver.find_element(
                    By.CSS_SELECTOR, '.spec-cve-id-meta-item .metadata-item-value')
                cve_id = cve_element.text
                print(f"{i} CVE ID FOUND", cve_id)

            except Exception as e:
                print(f"{i} No cve found...skipping")
                cve_id = "None"
        if cve_id == "None":
            i += 1
            continue
        cve_results.append({
            'cveid': cve_id,
            'link': "https://" + entry['link']
        })
        i += 1
    driver.quit()
    output_json = json.dumps(cve_results, indent=4)
    print(output_json)
    cve_results.extend(existing_cve_data)
    with open('cve_output.json', 'w') as file:
        json.dump(cve_results, file, indent=4)


if __name__ == '__main__':
    fetch()

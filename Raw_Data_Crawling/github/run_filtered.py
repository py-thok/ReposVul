"""
Filtered crawler for Mend.io CVE listings with CWE filtering.

This script is adapted from Raw_Data_Crawling/github/run.py.
It keeps the behavior of step_one (listing/crawling CVE entries)
and step_two (querying GitHub commit metadata), but only persists
entries whose CWE list contains any of the allowed CWE IDs below.

The goal is to reduce noise to crypto, randomness, key/credential,
PKI, cleartext, and password hashing related CWEs as specified.
"""

from bs4 import BeautifulSoup
import re
import os
import json
import time
import random
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from typing import Optional
import subprocess
from tqdm import tqdm, trange


# Allowed CWE IDs (string of numbers) based on the provided categories
ALLOWED_CWE_IDS = {
    # Crypto algo/impl/negotiation
    "326", "327", "328", "347", "329", "1204", "1240", "780", "757",
    # Randomness & entropy
    "330", "331", "332", "334", "335", "336", "337", "338", "339", "1241",
    # Key & credential management
    "321", "322", "323", "324", "798",
    # Certificates & PKI
    "295", "296", "297", "298", "299", "370", "599",
    # Cleartext transmission/storage
    "319", "523", "1428", "614", "1004", "311", "312", "313", "315", "316", "317", "318",
    # Password hashing
    "759", "760", "916",
}


def ensure_dirs(paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


def has_allowed_cwe(cwe_texts):
    """Return True if any CWE text contains an allowed CWE ID."""
    for t in cwe_texts:
        m = re.search(r"CWE-(\d+)", t)
        if m and m.group(1) in ALLOWED_CWE_IDS:
            return True
    return False


def _build_headers(referer: Optional[str] = None) -> dict:
    uas = [
        # A few common desktop browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ]
    hdrs = {
        "User-Agent": random.choice(uas),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        hdrs["Referer"] = referer
    else:
        hdrs["Referer"] = "https://www.mend.io/vulnerability-database/"
    return hdrs


def get_soup(url: str, referer: Optional[str] = None, max_retries: int = 5, base_delay: float = 0.5):
    """Fetch URL with headers + retries/backoff and return BeautifulSoup object, or None on failure."""
    last_exc = None
    for attempt in range(max_retries):
        try:
            req = Request(url, headers=_build_headers(referer))
            with urlopen(req, timeout=20) as resp:
                data = resp.read()
            return BeautifulSoup(data, "html.parser")
        except HTTPError as e:
            last_exc = e
            # Back off more on 403/429
            if e.code in (403, 429):
                sleep_s = base_delay * (2 ** attempt) + random.uniform(0.25, 0.45)
                time.sleep(sleep_s)
                continue
            else:
                time.sleep(attempt * 0.2)
                continue
        except URLError as e:
            last_exc = e
            time.sleep(base_delay + attempt)
            continue
        except Exception as e:
            last_exc = e
            time.sleep(0.2)
            continue
    print(f"Fetch failed after retries: {url} -> {last_exc}")
    return None


def step_one(Year, Month):
    YM = f"{Year}_{Month}"
    ensure_dirs(["logs", "results"])
    filename = f"logs/{YM}.log"
    res_filename = f"results/{YM}.jsonl"

    if not os.path.exists(filename):
        url = f"https://www.mend.io/vulnerability-database/full-listing/{Year}/{Month}"
        soup = get_soup(url)
        if soup is None:
            print(f"Skip {Year}-{Month}: initial page 403/failed")
            return

        links = []
        try:
            max_pagenumber = int(soup.find_all("li", class_="vuln-pagination-item")[-2].text.strip())
        except Exception:
            max_pagenumber = 1

        for link in soup.find_all("a", href=re.compile(r"^/vulnerability-database/CVE")):
            links.append((link.text, link.get("href")))

        if max_pagenumber > 1:
            for i in trange(2, max_pagenumber + 1, desc=f"Pages {YM}", unit="page"):
                url = f"https://www.mend.io/vulnerability-database/full-listing/{Year}/{Month}/{i}"
                soup = get_soup(url, referer=f"https://www.mend.io/vulnerability-database/full-listing/{Year}/{Month}")
                if soup is None:
                    print(f"Skip page {i} for {Year}-{Month}: 403/failed")
                    continue
                for link in soup.find_all("a", href=re.compile(r"^/vulnerability-database/CVE")):
                    links.append((link.text, link.get("href")))
                time.sleep(random.uniform(0.2, 0.5))

        with open(filename, "w", encoding="utf-8") as f:
            for _, href in links:
                f.write(href + "\n")

    with open(filename, "r", encoding="utf-8") as f:
        content = f.readlines()

    prefix = "https://www.mend.io"

    already_query_qid = 0
    if os.path.exists(res_filename):
        with open(res_filename, "r", encoding="utf-8") as f2:
            queried = f2.readlines()
            already_query_qid = json.loads(queried[-1]).get("q_id", 0) if queried else 0
            print(f"already query {already_query_qid}")

    for i in trange(len(content), desc=f"CVE details {YM}", unit="item"):
        try:
            time.sleep(random.uniform(0.1, 0.2))
            one_res = {
                "q_id": i,
                "cve_id": content[i].strip().split("/")[-1],
                "language": None,
                "date": None,
                "resources": [],
                "CWEs": [],
                "cvss": None,
                "description": None,
                "AV": None,
                "AC": None,
                "PR": None,
                "UI": None,
                "S": None,
                "C": None,
                "I": None,
                "A": None,
            }
            if i <= already_query_qid:
                continue

            fullweb_url = prefix + content[i].strip()
            soup = get_soup(fullweb_url, referer=prefix + "/vulnerability-database/")
            if soup is None:
                # If blocked for this item, skip silently
                continue
            time.sleep(random.uniform(0.2, 0.5))

            date = None
            language = None
            for tag in soup.find_all(["h4"]):
                if tag.name == "h4":
                    if "Date:" in tag.text:
                        date = tag.text.strip().replace("Date:", "").strip()
                    elif "Language:" in tag.text:
                        language = tag.text.strip().replace("Language:", "").strip()

            desc_div = soup.find("div", class_="single-vuln-desc no-good-to-know") or soup.find(
                "div", class_="single-vuln-desc"
            )
            if desc_div:
                desc = desc_div.find("p")
                if desc:
                    one_res["description"] = desc.text.strip()

            one_res["date"] = date
            one_res["language"] = language

            reference_links = []
            for div in soup.find_all("div", class_="reference-row"):
                for link in div.find_all("a", href=True):
                    reference_links.append(link["href"])
            one_res["resources"] = reference_links

            severity_score = ""
            div_score = soup.find("div", class_="ranger-value")
            if div_score:
                label = div_score.find("label")
                if label:
                    severity_score = label.text.strip()
            one_res["cvss"] = severity_score

            table = soup.find("table", class_="table table-report")
            if table:
                for tr in table.find_all("tr"):
                    th = tr.find("th").text.strip()
                    td = tr.find("td").text.strip()
                    if "Attack Vector" in th:
                        one_res["AV"] = td
                    elif "Attack Complexity" in th:
                        one_res["AC"] = td
                    elif "Privileges Required" in th:
                        one_res["PR"] = td
                    elif "User Interaction" in th:
                        one_res["UI"] = td
                    elif "Scope" in th:
                        one_res["S"] = td
                    elif "Confidentiality" in th:
                        one_res["C"] = td
                    elif "Integrity" in th:
                        one_res["I"] = td
                    elif "Availability" in th:
                        one_res["A"] = td

            cwe_numbers = []
            for div in soup.find_all("div", class_="light-box"):
                for link in div.find_all("a", href=True):
                    if "CWE" in link.text:
                        cwe_numbers.append(link.text)
            one_res["CWEs"] = cwe_numbers

            # Filter by allowed CWE list
            if not has_allowed_cwe(one_res["CWEs"]):
                continue

            if (
                one_res["cve_id"]
                and one_res["language"]
                and one_res["date"]
                and one_res["resources"]
                and one_res["CWEs"]
                and one_res["cvss"] is not None
            ):
                with open(res_filename, "a", encoding="utf-8") as f2:
                    jsonobj = json.dumps(one_res, ensure_ascii=False)
                    f2.write(jsonobj + "\n")
        except Exception as e:
            print(e)


def step_two(Year, Month):
    YM = f"{Year}_{Month}"
    res_filename = f"results/{YM}.jsonl"
    patch_name = f"crawl_result/{YM}_patch.jsonl"
    error_file = f"crawl_result/{YM}_patch_error.txt"
    ensure_dirs(["crawl_result"])

    if not os.path.exists(res_filename):
        return

    CVES = [json.loads(line) for line in open(res_filename, "r", encoding="utf-8")]
    querys = []
    fetchs = []
    for CVE in CVES:
        for res in CVE.get("resources", []):
            if "commit" in res and "github" in res:
                querys.append(
                    res.replace("/commit/", "/commits/").replace(
                        "https://github.com/", "https://api.github.com/repos/"
                    )
                )
    try:
        errors = []
        for query in querys:
            try:
                output = subprocess.check_output(
                    [
                        "curl",
                        "--request",
                        "GET",
                        "-H",
                        "Authorization: Bearer TODO",
                        "-H",
                        "X-GitHub-Api-Version: 2022-11-28",
                        "-u",
                        "KEY:",
                        query,
                    ]
                ).decode()
                data = json.loads(output)
            except Exception as e:
                print(e)
                continue
            if all(k in data for k in ("url", "html_url", "commit", "files")):
                fetchs.append(
                    {
                        "url": data["url"],
                        "html_url": data["html_url"],
                        "message": data["commit"]["message"],
                        "files": data["files"],
                        "commit_id": data["sha"],
                        "commit_date": data["commit"]["committer"]["date"],
                    }
                )
            else:
                print("Wrong! Data is NULL, see case ", query)
                errors.append(query)
            time.sleep(0.2)
    finally:
        with open(patch_name, "w", encoding="utf-8") as rf:
            rf.write(json.dumps(fetchs, indent=4, separators=(",", ": ")))
        with open(error_file, "w", encoding="utf-8") as rf:
            for err in errors:
                rf.write(err + "\n")

def main():
    Years = [str(year) for year in range(2024, 2026)]
    Months = [str(month) for month in range(1, 13)]
    for Year in Years:
        for Month in tqdm(Months):
            step_one(Year, Month)
    for Year in Years:
        for Month in tqdm(Months):
            step_two(Year, Month)


if __name__ == "__main__":
    main()

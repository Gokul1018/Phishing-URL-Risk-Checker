# Phishing URL Risk Checker

**Author:** Gokul S  
**Project type:** Beginner Cyber Security project

## Project description
This project checks a URL for common warning signs associated with suspicious links. It uses simple rules and returns a risk score (Low, Medium, or High) along with reasons.

## Features
- Checks whether HTTPS is used
- Checks for unusually long URLs and many subdomains
- Detects IP-address hosts and selected URL-shortening domains
- Looks for account-related keywords and hyphens in the domain
- Explains which rules increased the score
- Does not visit the submitted website

## Technologies used
- Python 3
- Jupyter Notebook
- Python standard library (`urllib.parse`, `ipaddress`)

## Files
- `GokulS_PhishingURLRiskChecker.ipynb` — notebook version
- `GokulS_PhishingURLRiskChecker.py` — standalone Python program
- `requirements.txt` — dependency list
- `GokulS_ProjectReport.docx` — project report

## Setup and run
1. Install Python 3.10 or later.
2. (Optional) Create and activate a virtual environment.
3. Install listed dependencies (none are required):
   ```bash
   pip install -r requirements.txt
   ```
4. Run the Python program:
   ```bash
   python GokulS_PhishingURLRiskChecker.py
   ```
5. Or open the `.ipynb` file in Jupyter Notebook and run the cells from top to bottom.

## Dataset
No external dataset is required. The notebook uses a small set of illustrative sample URLs for demonstration. These samples are not a labeled research dataset.

## Limitations and safety
This is a learning project, not a production phishing detector. Rule-based checks can produce false positives and false negatives. HTTPS alone does not mean a website is trustworthy. Do not enter passwords or sensitive information into suspicious sites. Verify important links through official websites or trusted security tools.

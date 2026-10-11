# IP Scan Pro (Python)

A small Streamlit web app for authorized TCP port scanning and discovery of hosts on a small IPv4 network.

## Requirements
- Python 3.10 or newer
- Network access to the hosts you are authorized to scan

## Run on Windows, macOS, or Linux
1. Extract this folder.
2. Open a terminal in this folder.
3. Create a virtual environment (recommended):
   - Windows: `py -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies: `python -m pip install -r requirements.txt`
5. Start the app: `streamlit run app.py`
6. Open the local address Streamlit prints (usually `http://localhost:8501`).

## Features
- TCP port scan for a single host
- Small IPv4 CIDR host discovery (maximum 256 addresses per run)
- Adjustable timeout and concurrency
- CSV export

Use only on networks and systems you own or have explicit permission to assess. This is a TCP reachability scanner, not a vulnerability scanner.

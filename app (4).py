import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import streamlit as st

st.set_page_config(page_title="IP Scan Pro", page_icon="🔎", layout="wide")

st.title("🔎 IP Scan Pro")
st.caption("A simple Python IP and network scanner for networks you own or have permission to test.")

with st.sidebar:
    st.header("Scan settings")
    timeout = st.slider("Connection timeout (seconds)", 0.2, 3.0, 0.7, 0.1)
    workers = st.slider("Concurrent checks", 1, 128, 32)
    show_closed = st.checkbox("Show closed/unreachable ports", value=False)
    st.markdown("---")
    st.warning("Only scan systems and networks you own or are authorized to assess.")

tab_host, tab_network = st.tabs(["Single host", "Local network / CIDR"])

def check_port(host, port, timeout_value):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout_value)
            result = sock.connect_ex((host, port))
            return result == 0
    except (OSError, socket.gaierror):
        return False

def scan_host(host, ports, timeout_value, max_workers):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_port, host, port, timeout_value): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                is_open = future.result()
            except Exception:
                is_open = False
            results.append({"Host": host, "Port": port, "State": "OPEN" if is_open else "CLOSED / FILTERED"})
    return sorted(results, key=lambda row: row["Port"])

def parse_ports(raw):
    ports = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text.strip()), int(end_text.strip())
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.add(port)
    if not ports:
        raise ValueError("Enter at least one port.")
    if len(ports) > 2000:
        raise ValueError("Please scan no more than 2000 ports per run.")
    return sorted(ports)

with tab_host:
    st.subheader("Scan a host")
    host_input = st.text_input("IP address or hostname", value="127.0.0.1", key="host")
    ports_input = st.text_input("Ports (examples: 22,80,443 or 1-1024)", value="22,80,443,8080")
    if st.button("Scan host", type="primary"):
        try:
            host = host_input.strip()
            if not host:
                raise ValueError("Enter an IP address or hostname.")
            # Resolve hostname and validate the resulting IPv4 address.
            resolved = socket.gethostbyname(host)
            ports = parse_ports(ports_input)
            with st.spinner(f"Scanning {host} ({resolved})…"):
                results = scan_host(resolved, ports, timeout, workers)
            visible = results if show_closed else [r for r in results if r["State"] == "OPEN"]
            st.success(f"Scan finished. {sum(r['State'] == 'OPEN' for r in results)} open port(s) found.")
            if visible:
                st.dataframe(visible, use_container_width=True, hide_index=True)
                st.download_button("Download CSV", data=__import__("pandas").DataFrame(results).to_csv(index=False),
                                   file_name="ip_scan_results.csv", mime="text/csv")
            else:
                st.info("No open ports found among the selected ports.")
        except (ValueError, OSError, socket.gaierror) as exc:
            st.error(f"Could not run scan: {exc}")

with tab_network:
    st.subheader("Discover hosts on a small IPv4 network")
    cidr_input = st.text_input("IPv4 network in CIDR notation", value="192.168.1.0/24")
    common_port = st.selectbox("Port used to identify reachable hosts", [80, 443, 22, 445, 3389, 53])
    if st.button("Discover hosts"):
        try:
            network = ipaddress.ip_network(cidr_input.strip(), strict=False)
            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError("Please enter an IPv4 network.")
            if network.num_addresses > 256:
                raise ValueError("For safety and performance, scan at most 256 addresses per run.")
            hosts = list(network.hosts())
            found = []
            progress = st.progress(0)
            status = st.empty()
            def probe(ip):
                return check_port(str(ip), common_port, timeout)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(probe, ip): ip for ip in hosts}
                done = 0
                for future in as_completed(futures):
                    ip = futures[future]
                    done += 1
                    status.text(f"Checked {done}/{len(hosts)} addresses…")
                    progress.progress(done / max(1, len(hosts)))
                    try:
                        if future.result():
                            try:
                                name = socket.gethostbyaddr(str(ip))[0]
                            except OSError:
                                name = ""
                            found.append({"IP address": str(ip), "Reverse DNS": name, "Port": common_port, "State": "OPEN"})
                    except Exception:
                        pass
            if found:
                st.success(f"Found {len(found)} host(s) responding on port {common_port}.")
                st.dataframe(sorted(found, key=lambda row: ipaddress.ip_address(row["IP address"])),
                             use_container_width=True, hide_index=True)
                st.download_button("Download CSV", data=__import__("pandas").DataFrame(found).to_csv(index=False),
                                   file_name="network_discovery.csv", mime="text/csv")
            else:
                st.info("No hosts responded on the selected port. A host may be online but block that port.")
        except ValueError as exc:
            st.error(f"Invalid network: {exc}")

st.markdown("---")
st.caption("Note: this checks TCP ports only. Firewalls may hide services, and an open port does not prove a vulnerability.")

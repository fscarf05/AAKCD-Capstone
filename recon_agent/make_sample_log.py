"""Generate a realistic Zeek conn.log (TSV) with benign traffic + two scans, for testing without a lab."""
import random

random.seed(7)
FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "conn_state"]
HEADER = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
          "#path\tconn", "#fields\t" + "\t".join(FIELDS)]
T0 = 1_790_000_000.0
rows = []


def add(ts, src, dst, dport, proto, service, state):
    uid = "C" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=17))
    rows.append([f"{ts:.6f}", uid, src, str(random.randint(40000, 65000)), dst, str(dport), proto, service, state])


# Benign: 3 clients browsing / DNS over 5 minutes
for i in range(300):
    client = random.choice(["192.168.56.21", "192.168.56.22", "192.168.56.23"])
    if random.random() < 0.6:
        add(T0 + i, client, random.choice(["142.250.66.78", "104.18.32.7"]), 443, "tcp", "ssl", "SF")
    else:
        add(T0 + i, client, "192.168.56.1", 53, "udp", "dns", "SF")

# Vertical SYN scan (nmap -sS, top 1000 ports) from attacker .10 against victim .20 over ~8s
open_ports = {22, 80, 443}
for n, port in enumerate(random.sample(range(1, 10000), 1000)):
    state = "RSTO" if port in open_ports else random.choice(["REJ", "REJ", "S0"])
    add(T0 + 60 + n * 0.008, "192.168.56.10", "192.168.56.20", port, "tcp", "-", state)

# Horizontal sweep for SSH across the /24 from .11 over ~25s
for host in range(1, 51):
    add(T0 + 120 + host * 0.5, "192.168.56.11", f"192.168.56.{host}", 22, "tcp", "-",
        "RSTO" if host in (20, 30) else "S0")

rows.sort(key=lambda r: float(r[0]))
with open("sample_conn.log", "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(HEADER) + "\n")
    for r in rows:
        f.write("\t".join(r) + "\n")
print(f"Wrote sample_conn.log with {len(rows)} connections")

import csv

FAILED_LOGIN_THRESHOLD = 10

with open('sample.log', 'r') as file:
    log_lines = file.readlines()

ip_c = {}
endpoint_c = {}
failed_log = {}

for line in log_lines:
    parts = line.split()
    if len(parts) > 6:
        ip_address = parts[0]
        endpoint = parts[6]
        status_code = parts[8]
        message = " ".join(parts[9:])

        if ip_address in ip_c:
            ip_c[ip_address] += 1
        else:
            ip_c[ip_address] = 1

        if endpoint in endpoint_c:
            endpoint_c[endpoint] += 1
        else:
            endpoint_c[endpoint] = 1

        if status_code == "401" or "Invalid credentials" in message:
            if ip_address in failed_log:
                failed_log[ip_address] += 1
            else:
                failed_log[ip_address] = 1

most_frequent_endpoint = max(endpoint_c.items(), key=lambda x: x[1])

susp_ip = {ip: count for ip, count in failed_log.items() if count > FAILED_LOGIN_THRESHOLD}

print("Requests per IP:")
print(f"{'IP Address':<20} {'Request Count':<15}")
for ip, count in sorted(ip_c.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip:<20} {count:<15}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_frequent_endpoint[0]} (Accessed {most_frequent_endpoint[1]} times)")

print("\nSuspicious Activity Detected:")
print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
for ip, count in susp_ip.items():
    print(f"{ip:<20} {count:<20}")

with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    fieldnames = ['Category', 'IP Address', 'Request Count', 'Endpoint', 'Access Count', 'Failed Login Count']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    
    for ip, count in sorted(ip_c.items(), key=lambda x: x[1], reverse=True):
        writer.writerow({'Category': 'Requests per IP', 'IP Address': ip, 'Request Count': count, 'Endpoint': '', 'Access Count': '', 'Failed Login Count': ''})
    
    writer.writerow({'Category': 'Most Accessed Endpoint', 'IP Address': '', 'Request Count': '', 'Endpoint': most_frequent_endpoint[0], 'Access Count': most_frequent_endpoint[1], 'Failed Login Count': ''})
    
    for ip, count in susp_ip.items():
        writer.writerow({'Category': 'Suspicious Activity', 'IP Address': ip, 'Request Count': '', 'Endpoint': '', 'Access Count': '', 'Failed Login Count': count})

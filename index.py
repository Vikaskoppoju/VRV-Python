import csv

def count_requests_per_ip(log_file):
    ip_counts = {}
    with open(log_file, 'r') as file:
        for line in file:
            parts = line.split()
            ip = parts[0]
            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1
    return ip_counts

def most_accessed_endpoint(log_file):
    endpoint_counts = {}
    with open(log_file, 'r') as file:
        for line in file:
            parts = line.split()
            endpoint = parts[6]
            if endpoint in endpoint_counts:
                endpoint_counts[endpoint] += 1
            else:
                endpoint_counts[endpoint] = 1
    most_accessed = max(endpoint_counts, key=endpoint_counts.get)
    return most_accessed, endpoint_counts[most_accessed]

def detect_suspicious_activity(log_file, threshold=10):
    failed_logins = {}
    suspicious_ips = []
    with open(log_file, 'r') as file:
        for line in file:
            parts = line.split()
            status_code = parts[8]
            ip = parts[0]
            if status_code == '401':
                if ip in failed_logins:
                    failed_logins[ip] += 1
                else:
                    failed_logins[ip] = 1
                if failed_logins[ip] > threshold:
                    suspicious_ips.append((ip, failed_logins[ip]))
    return suspicious_ips

def save_to_csv(ip_counts, most_accessed, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips:
            writer.writerow([ip, count])

log_file = 'sample.log'
ip_counts = count_requests_per_ip(log_file)
most_accessed = most_accessed_endpoint(log_file)
suspicious_ips = detect_suspicious_activity(log_file)

print("IP Address           Request Count")
for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip:<25}{count:<15}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

print("\nSuspicious Activity Detected:")
print("IP Address           Failed Login Attempts")
for ip, count in suspicious_ips:
    print(f"{ip}        {count}")

save_to_csv(ip_counts, most_accessed, suspicious_ips)

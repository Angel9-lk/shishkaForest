SELECT src.ip_address AS source_ip, COUNT(f.flow_id) AS total_flows, 
SUM(f.total_fwd_packets) AS total_packets_sent, GROUP_CONCAT(DISTINCT l.label_name) AS attack_types_generated
FROM traffic_flows AS f
JOIN ip_addresses AS src ON src.ip_address_id = f.source_ip_id
JOIN attack_labels AS l ON l.label_id = f.label_id
WHERE LOWER(TRIM(l.label_name)) != 'benign' AND f.source_ip_id NOT IN (SELECT ip_address_id FROM whitelisted_ips WHERE enabled = 1)
GROUP BY src.ip_address
HAVING COUNT(f.flow_id) > 5 
ORDER BY total_packets_sent DESC;

SELECT l.label_name AS attack_type, COUNT(*) AS attack_count
FROM traffic_flows f
JOIN attack_labels l ON f.label_id = l.label_id
WHERE f.source_ip_id = (SELECT ip_address_id FROM ip_addresses WHERE ip_address = 2886729729) AND l.label_name != 'benign'
GROUP BY l.label_name;
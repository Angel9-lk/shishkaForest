WITH scored AS (
 SELECT
f.flow_id,
src.ip_address AS source_ip,
f.source_port,
dst.ip_address AS destination_ip,
f.destination_port,
p.protocol_name,
f.observed_at,
f.flow_duration,
f.total_fwd_packets,
f.total_backward_packets,
l.label_name AS dataset_label,


duration_stats.q1 AS duration_q1,
duration_stats.q2_median AS duration_median,
duration_stats.q3 AS duration_q3,
duration_stats.iqr AS duration_iqr,
duration_stats.upper_bound AS duration_upper_bound,


fwd_stats.q1 AS fwd_q1,
fwd_stats.q2_median AS fwd_median,
fwd_stats.q3 AS fwd_q3,
fwd_stats.iqr AS fwd_iqr,
fwd_stats.upper_bound AS fwd_upper_bound,


bwd_stats.q1 AS bwd_q1,
bwd_stats.q2_median AS bwd_median,
bwd_stats.q3 AS bwd_q3,
bwd_stats.iqr AS bwd_iqr,
bwd_stats.upper_bound AS bwd_upper_bound,


CASE
WHEN f.flow_duration > duration_stats.upper_bound
AND f.flow_duration >= 0
THEN 1 ELSE 0
END AS duration_outlier,


CASE
WHEN f.total_fwd_packets > fwd_stats.upper_bound
THEN 1 ELSE 0
END AS fwd_outlier,


CASE
WHEN f.total_backward_packets > bwd_stats.upper_bound
THEN 1 ELSE 0
END AS bwd_outlier


FROM traffic_flows AS f
JOIN ip_addresses AS src
ON src.ip_address_id = f.source_ip_id
JOIN ip_addresses AS dst
ON dst.ip_address_id = f.destination_ip_id
JOIN protocols AS p
ON p.protocol_id = f.protocol_id
JOIN attack_labels AS l
ON l.label_id = f.label_id
JOIN feature_statistics AS duration_stats
ON duration_stats.feature_name = 'Flow Duration'
JOIN feature_statistics AS fwd_stats
ON fwd_stats.feature_name = 'Total Fwd Packets'
JOIN feature_statistics AS bwd_stats
ON bwd_stats.feature_name = 'Total Backward Packets'
),
results AS (
SELECT
*,
 duration_outlier + fwd_outlier + bwd_outlier AS anomaly_score
FROM scored
)
SELECT
 flow_id,
 source_ip,
 source_port,
 destination_ip,
 destination_port,
 protocol_name,
 observed_at,
 flow_duration,
 total_fwd_packets,
 total_backward_packets,
 dataset_label,


 duration_outlier,
 fwd_outlier,
 bwd_outlier,
 anomaly_score,


 duration_upper_bound,
 fwd_upper_bound,
 bwd_upper_bound,


CASE
WHEN anomaly_score >= 2 THEN 'Аномалия'
WHEN anomaly_score = 1 THEN 'Требует проверки'
ELSE 'Норма'
END AS detection_result


FROM results
WHERE anomaly_score >= 1
ORDER BY anomaly_score DESC, flow_id;
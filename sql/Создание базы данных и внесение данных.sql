-- 1. Создаем промежуточную чистую таблицу
DROP TABLE IF EXISTS staging_clean;
CREATE TABLE staging_clean (
    source_ip TEXT, source_port INTEGER, destination_ip TEXT, destination_port INTEGER, protocol INTEGER,
    timestamp TEXT, flow_duration REAL, total_fwd_packets INTEGER, total_backward_packets INTEGER,
    total_length_fwd REAL, total_length_bwd REAL, fwd_packet_length_max REAL, fwd_packet_length_min REAL,
    fwd_packet_length_mean REAL, fwd_packet_length_std REAL, bwd_packet_length_max REAL, bwd_packet_length_min REAL,
    bwd_packet_length_mean REAL, bwd_packet_length_std REAL, flow_iat_mean REAL, flow_iat_std REAL,
    flow_iat_max REAL, flow_iat_min REAL, fwd_iat_total REAL, fwd_iat_mean REAL, fwd_iat_std REAL,
    fwd_iat_max REAL, fwd_iat_min REAL, bwd_iat_total REAL, bwd_iat_mean REAL, bwd_iat_std REAL,
    bwd_iat_max REAL, bwd_iat_min REAL, fwd_psh_flags INTEGER, fwd_urg_flags INTEGER, fwd_header_length INTEGER,
    bwd_header_length INTEGER, fwd_packets_per_second REAL, bwd_packets_per_second REAL, min_packet_length REAL,
    max_packet_length REAL, packet_length_mean REAL, packet_length_std REAL, packet_length_variance REAL,
    fin_flag_count INTEGER, syn_flag_count INTEGER, rst_flag_count INTEGER, psh_flag_count INTEGER, ack_flag_count INTEGER,
    urg_flag_count INTEGER, cwe_flag_count INTEGER, ece_flag_count INTEGER, down_up_ratio REAL, average_packet_size REAL,
    avg_fwd_segment_size REAL, avg_bwd_segment_size REAL, subflow_fwd_packets INTEGER, subflow_fwd_bytes REAL,
    subflow_bwd_packets INTEGER, subflow_bwd_bytes REAL, init_win_bytes_forward INTEGER, init_win_bytes_backward INTEGER,
    act_data_pkt_fwd INTEGER, min_seg_size_forward REAL, active_mean REAL, active_std REAL, active_max REAL,
    active_min REAL, idle_mean REAL, idle_std REAL, idle_max REAL, idle_min REAL, label TEXT
);

-- 2. Переносим данные "вслепую" по позициям колонок из вашей существующей таблицы
INSERT INTO staging_clean SELECT * FROM staging_traffic;

-- 3. Наполняем связанные справочники
INSERT OR IGNORE INTO ip_addresses (ip_address, address_type)
SELECT DISTINCT source_ip, 'encoded_ipv4' FROM staging_clean WHERE source_ip IS NOT NULL AND source_ip != ''
UNION
SELECT DISTINCT destination_ip, 'encoded_ipv4' FROM staging_clean WHERE destination_ip IS NOT NULL AND destination_ip != '';

INSERT OR IGNORE INTO protocols (protocol_number, protocol_name)
SELECT DISTINCT protocol, 
       CASE protocol 
            WHEN 6 THEN 'TCP' 
            WHEN 17 THEN 'UDP' 
            WHEN 1 THEN 'ICMP' 
            ELSE 'UNKNOWN_' || protocol 
       END
FROM staging_clean WHERE protocol IS NOT NULL;

INSERT OR IGNORE INTO attack_labels (label_name, is_benign)
SELECT DISTINCT LOWER(trim(label)), CASE WHEN LOWER(trim(label)) = 'benign' THEN 1 ELSE 0 END
FROM staging_clean WHERE label IS NOT NULL AND label != '';
-- 4. Переносим данные в целевую таблицу traffic_flows
INSERT INTO traffic_flows (
    source_ip_id, source_port, destination_ip_id, destination_port, protocol_id,
    observed_at, flow_duration, total_fwd_packets, total_backward_packets,
    total_length_fwd, total_length_bwd, fwd_packet_length_max, fwd_packet_length_min,
    fwd_packet_length_mean, fwd_packet_length_std, bwd_packet_length_max, bwd_packet_length_min,
    bwd_packet_length_mean, bwd_packet_length_std, flow_iat_mean, flow_iat_std,
    flow_iat_max, flow_iat_min, fwd_iat_total, fwd_iat_mean, fwd_iat_std,
    fwd_iat_max, fwd_iat_min, bwd_iat_total, bwd_iat_mean, bwd_iat_std,
    bwd_iat_max, bwd_iat_min, fwd_psh_flags, fwd_urg_flags, fwd_header_length,
    bwd_header_length, fwd_packets_per_second, bwd_packets_per_second, min_packet_length,
    max_packet_length, packet_length_mean, packet_length_std, packet_length_variance,
    fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count, ack_flag_count,
    urg_flag_count, cwe_flag_count, ece_flag_count, down_up_ratio, average_packet_size,
    avg_fwd_segment_size, avg_bwd_segment_size, subflow_fwd_packets, subflow_fwd_bytes,
    subflow_bwd_packets, subflow_bwd_bytes, init_win_bytes_forward, init_win_bytes_backward,
    act_data_pkt_fwd, min_seg_size_forward, active_mean, active_std, active_max,
    active_min, idle_mean, idle_std, idle_max, idle_min, label_id
)
SELECT 
    src.ip_address_id, st.source_port, dst.ip_address_id, st.destination_port, p.protocol_id,
    COALESCE(st.timestamp, datetime('now')), st.flow_duration, st.total_fwd_packets, st.total_backward_packets,
    st.total_length_fwd, st.total_length_bwd, st.fwd_packet_length_max, st.fwd_packet_length_min,
    st.fwd_packet_length_mean, st.fwd_packet_length_std, st.bwd_packet_length_max, st.bwd_packet_length_min,
    st.bwd_packet_length_mean, st.bwd_packet_length_std, st.flow_iat_mean, st.flow_iat_std,
    st.flow_iat_max, st.flow_iat_min, st.fwd_iat_total, st.fwd_iat_mean, st.fwd_iat_std,
    st.fwd_iat_max, st.fwd_iat_min, st.bwd_iat_total, st.bwd_iat_mean, st.bwd_iat_std,
    st.bwd_iat_max, st.bwd_iat_min, st.fwd_psh_flags, st.fwd_urg_flags, st.fwd_header_length,
    st.bwd_header_length, st.fwd_packets_per_second, st.bwd_packets_per_second, st.min_packet_length,
    st.max_packet_length, st.packet_length_mean, st.packet_length_std, st.packet_length_variance,
    st.fin_flag_count, st.syn_flag_count, st.rst_flag_count, st.psh_flag_count, st.ack_flag_count,
    st.urg_flag_count, st.cwe_flag_count, st.ece_flag_count, st.down_up_ratio, st.average_packet_size,
    st.avg_fwd_segment_size, st.avg_bwd_segment_size, st.subflow_fwd_packets, st.subflow_fwd_bytes,
    st.subflow_bwd_packets, st.subflow_bwd_bytes, st.init_win_bytes_forward, st.init_win_bytes_backward,
    st.act_data_pkt_fwd, st.min_seg_size_forward, st.active_mean, st.active_std, st.active_max,
    st.active_min, st.idle_mean, st.idle_std, st.idle_max, st.idle_min, lbl.label_id
FROM staging_clean st
JOIN ip_addresses src ON src.ip_address = st.source_ip
JOIN ip_addresses dst ON dst.ip_address = st.destination_ip
JOIN protocols p ON p.protocol_number = st.protocol
JOIN attack_labels lbl ON lbl.label_name = LOWER(trim(st.label));

-- 5. Удаляем промежуточную чистую таблицу
DROP TABLE IF EXISTS staging_clean;
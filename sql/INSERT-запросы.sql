-- Добавляю в таблицу локальный адрес
INSERT INTO ip_addresses (ip_address, address_type) 
VALUES ('3232235521', 'encoded_ipv4'); 

-- Добавляю в таблицу публичный DNS
INSERT INTO ip_addresses (ip_address, address_type) 
VALUES ('134744072', 'encoded_ipv4');

-- Добавляю IP в белый список
INSERT INTO whitelisted_ips (ip_address_id, description, enabled)
SELECT ip_address_id, 'Доверенный IP администратора', 1
FROM ip_addresses WHERE ip_address = '3232235521';

Добавим IP, чтобы далее создать атаку
INSERT INTO ip_addresses (ip_address, address_type) VALUES 
('167772210', 'encoded_ipv4');

INSERT INTO traffic_flows (
  source_ip_id, source_port, destination_ip_id, destination_port, protocol_id, observed_at, flow_duration, 
  total_fwd_packets, total_backward_packets, total_length_fwd, total_length_bwd, 
  fwd_packet_length_max, fwd_packet_length_min, fwd_packet_length_mean, fwd_packet_length_std,
  bwd_packet_length_max, bwd_packet_length_min, bwd_packet_length_mean, bwd_packet_length_std,
  flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
  fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
  bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
  fwd_psh_flags, fwd_urg_flags, fwd_header_length, bwd_header_length,
  fwd_packets_per_second, bwd_packets_per_second, min_packet_length, max_packet_length, 
  packet_length_mean, packet_length_std, packet_length_variance,
  fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count, ack_flag_count, urg_flag_count, cwe_flag_count, 
  ece_flag_count,down_up_ratio, average_packet_size, avg_fwd_segment_size, avg_bwd_segment_size,
  subflow_fwd_packets, subflow_fwd_bytes, subflow_bwd_packets, subflow_bwd_bytes,
  init_win_bytes_forward, init_win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,
  active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max, idle_min, label_id) 
VALUES (
  (SELECT ip_address_id FROM ip_addresses WHERE ip_address = '167772210'), 55555, 
  (SELECT ip_address_id FROM ip_addresses WHERE ip_address = '134744072'), 80, 
  (SELECT protocol_id FROM protocols WHERE protocol_name = 'TCP'), '2026-10-30 12:00:00', 
  1000, 15000, 0, 750000.0, 0, 1500, 0, 750, 100, 0, 0, 0, 0, 10, 5, 20, 1, 100, 10, 5, 20, 1, 0, 0, 0, 0, 0,      
  0, 0, 20, 20, 15000, 0, 0, 1500, 750, 100, 562500, 0, 1, 0, 0, 0, 0, 0, 0, 0, 750, 750, 0, 15000, 750000, 0, 0,     
  0, 0, 15000, 20, 0, 0, 0, 0, 0, 0, 0, 0, (SELECT label_id FROM attack_labels WHERE label_name = 'hulk')
);



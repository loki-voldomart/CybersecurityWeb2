-- Seed sample cybersecurity data for testing and demonstration

-- Insert sample system status data
INSERT INTO system_status (component, status, cpu_usage, memory_usage, disk_usage, network_throughput) VALUES
('firewall', 'online', 15.5, 32.1, 45.8, 1024000),
('ids', 'online', 22.3, 28.7, 52.3, 2048000),
('antivirus', 'warning', 45.2, 67.8, 78.9, 512000),
('network_monitor', 'online', 12.1, 25.4, 35.2, 4096000);

-- Insert sample threat events
INSERT INTO threat_events (threat_type, severity, source_ip, target_ip, port, description, status) VALUES
('dos', 'high', '192.168.1.100', '10.0.0.1', 80, 'High volume of requests detected from single IP', 'active'),
('port_scan', 'medium', '203.0.113.45', '10.0.0.1', NULL, 'Sequential port scanning detected', 'investigating'),
('malware', 'critical', '198.51.100.23', '10.0.0.5', 443, 'Suspicious payload detected in HTTPS traffic', 'blocked'),
('phishing', 'medium', '192.0.2.15', '10.0.0.3', 25, 'Phishing email attempt detected', 'resolved'),
('dos', 'critical', '203.0.113.67', '10.0.0.1', 443, 'DDoS attack in progress - multiple source IPs', 'active');

-- Insert sample network logs
INSERT INTO network_logs (source_ip, destination_ip, source_port, destination_port, protocol, packet_size, threat_score, is_suspicious) VALUES
('192.168.1.100', '10.0.0.1', 54321, 80, 'TCP', 1500, 0.85, true),
('203.0.113.45', '10.0.0.1', 45678, 22, 'TCP', 64, 0.65, true),
('198.51.100.23', '10.0.0.5', 33445, 443, 'TCP', 2048, 0.95, true),
('10.0.0.2', '8.8.8.8', 53421, 53, 'UDP', 128, 0.1, false),
('192.0.2.15', '10.0.0.3', 25678, 25, 'TCP', 512, 0.75, true);

-- Insert sample defense actions
INSERT INTO defense_actions (threat_event_id, action_type, action_status, executed_at, executed_by, details) 
SELECT 
    id, 
    'block_ip', 
    'executed', 
    NOW() - INTERVAL '5 minutes', 
    'auto_defense_system',
    'IP address blocked due to malicious activity'
FROM threat_events 
WHERE threat_type = 'malware' AND severity = 'critical'
LIMIT 1;

INSERT INTO defense_actions (threat_event_id, action_type, action_status, executed_at, executed_by, details)
SELECT 
    id, 
    'investigate', 
    'pending', 
    NULL,
    NULL,
    'Port scanning activity requires manual investigation'
FROM threat_events 
WHERE threat_type = 'port_scan'
LIMIT 1;

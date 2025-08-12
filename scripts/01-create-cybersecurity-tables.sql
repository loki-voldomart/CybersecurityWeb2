-- Create cybersecurity database schema
-- This script creates tables for storing threat events, network logs, and system status

-- Enable Row Level Security and real-time features
ALTER DATABASE postgres SET "app.jwt_secret" TO 'your-jwt-secret';

-- Create threat_events table
CREATE TABLE IF NOT EXISTS threat_events (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    threat_type VARCHAR(50) NOT NULL, -- 'dos', 'port_scan', 'malware', 'phishing'
    severity VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    source_ip INET NOT NULL,
    target_ip INET,
    port INTEGER,
    description TEXT,
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'blocked', 'investigating', 'resolved'
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create network_logs table
CREATE TABLE IF NOT EXISTS network_logs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10), -- 'TCP', 'UDP', 'ICMP'
    packet_size INTEGER,
    flags VARCHAR(50),
    payload_hash VARCHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_score DECIMAL(3,2) DEFAULT 0.0, -- 0.0 to 1.0
    is_suspicious BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'
);

-- Create system_status table
CREATE TABLE IF NOT EXISTS system_status (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    component VARCHAR(50) NOT NULL, -- 'firewall', 'ids', 'antivirus', 'network_monitor'
    status VARCHAR(20) NOT NULL, -- 'online', 'offline', 'warning', 'error'
    cpu_usage DECIMAL(5,2),
    memory_usage DECIMAL(5,2),
    disk_usage DECIMAL(5,2),
    network_throughput BIGINT,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Create defense_actions table
CREATE TABLE IF NOT EXISTS defense_actions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    threat_event_id UUID REFERENCES threat_events(id),
    action_type VARCHAR(50) NOT NULL, -- 'block_ip', 'quarantine', 'alert', 'investigate'
    action_status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'executed', 'failed'
    executed_at TIMESTAMP WITH TIME ZONE,
    executed_by VARCHAR(100),
    details TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_threat_events_type ON threat_events(threat_type);
CREATE INDEX IF NOT EXISTS idx_threat_events_severity ON threat_events(severity);
CREATE INDEX IF NOT EXISTS idx_threat_events_status ON threat_events(status);
CREATE INDEX IF NOT EXISTS idx_threat_events_detected_at ON threat_events(detected_at);
CREATE INDEX IF NOT EXISTS idx_network_logs_timestamp ON network_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_network_logs_source_ip ON network_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_network_logs_suspicious ON network_logs(is_suspicious);
CREATE INDEX IF NOT EXISTS idx_system_status_component ON system_status(component);

-- Enable Row Level Security
ALTER TABLE threat_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE defense_actions ENABLE ROW LEVEL SECURITY;

-- Create policies (allow all for now - in production, add proper auth)
CREATE POLICY "Allow all operations on threat_events" ON threat_events FOR ALL USING (true);
CREATE POLICY "Allow all operations on network_logs" ON network_logs FOR ALL USING (true);
CREATE POLICY "Allow all operations on system_status" ON system_status FOR ALL USING (true);
CREATE POLICY "Allow all operations on defense_actions" ON defense_actions FOR ALL USING (true);

-- Enable real-time subscriptions
ALTER PUBLICATION supabase_realtime ADD TABLE threat_events;
ALTER PUBLICATION supabase_realtime ADD TABLE network_logs;
ALTER PUBLICATION supabase_realtime ADD TABLE system_status;
ALTER PUBLICATION supabase_realtime ADD TABLE defense_actions;

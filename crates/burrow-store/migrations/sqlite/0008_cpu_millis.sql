-- A node's CPU is charged in thousandths of a CPU, so a sandbox capped below
-- its vCPUs takes only its cap.
ALTER TABLE nodes RENAME COLUMN committed_vcpus TO committed_cpu_millis;
ALTER TABLE nodes RENAME COLUMN reserved_vcpus TO reserved_cpu_millis;
UPDATE nodes SET committed_cpu_millis = committed_cpu_millis * 1000,
                 reserved_cpu_millis = reserved_cpu_millis * 1000;

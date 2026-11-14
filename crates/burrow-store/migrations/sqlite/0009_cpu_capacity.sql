-- What a node may commit to sandboxes is its cores times its
-- --cpu-overcommit, in thousandths of a CPU, which the reservation checks in
-- place of its cores.
ALTER TABLE nodes RENAME COLUMN total_vcpus TO cpu_capacity_millis;
UPDATE nodes SET cpu_capacity_millis = cpu_capacity_millis * 1000;

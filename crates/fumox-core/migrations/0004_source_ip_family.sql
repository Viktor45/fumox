-- Per-source IP protocol family for fetching the URL (SPEC §10.1, §16).
-- TEXT: NULL = inherit the deployment default ([fetch] ip_family);
-- 'any' = dual-stack (first IPv4 address, IPv6 fallback); 'ipv4' / 'ipv6'
-- restrict the connect address to that family strictly.
ALTER TABLE sources ADD COLUMN ip_family TEXT;

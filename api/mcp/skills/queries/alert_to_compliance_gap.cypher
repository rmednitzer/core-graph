match (a:MonitoringAlert {alertname: $alertname})-[:monitors]->(h:Host)
optional match (cc:ComplianceControl)-[:controls]->(h)
optional match (cc)<-[:evidenced_by]-(er:EvidenceRecord)
with a, h, cc, er,
     case
       when er is null then 'missing'
       when er.created_at < toString(localdatetime() - duration('P30D')) then 'stale'
       else 'current'
     end as evidence_status
where evidence_status <> 'current'
return a.alertname as alertname,
       h.name as host_name,
       h.canonical_key as host_key,
       cc.control_id as control_id,
       evidence_status,
       er.created_at as last_evidence

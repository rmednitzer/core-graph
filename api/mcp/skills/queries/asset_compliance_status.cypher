match (h:Host {canonical_key: $canonical_key})
optional match (cc:ComplianceControl)-[:controls]->(h)
optional match (cc)-[:satisfies]->(fw:Framework)
optional match (cc)<-[:evidenced_by]-(er:EvidenceRecord)
return cc.control_id as control_id,
       fw.name as framework_name,
       er.created_at as last_evidence_timestamp,
       case
         when er is null then 'missing'
         when er.created_at < toString(localdatetime() - duration('P30D')) then 'stale'
         else 'current'
       end as evidence_status

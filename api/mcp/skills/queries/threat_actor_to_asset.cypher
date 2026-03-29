match (ta:ThreatActor {name: $threat_actor_name})
optional match (ta)-[:uses]->(ap)
optional match (ap)-[:indicates]->(v:Vulnerability)
optional match (v)<-[:indicates]-(ind:Indicator)-[:observed_on]->(ip:CanonicalIP)
optional match (ip)<-[:observed_as]-(h:Host)
optional match (a:MonitoringAlert)-[:monitors]->(h)
  where a.status = 'firing'
return h.name as asset_name,
       h.canonical_key as asset_key,
       v.cve_id as cve_id,
       v.severity as vuln_severity,
       a is not null as has_active_alert,
       collect(distinct ap.name) as attack_patterns

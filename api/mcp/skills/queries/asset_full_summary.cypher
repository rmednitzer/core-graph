match (h:Host {canonical_key: $canonical_key})
optional match (a:MonitoringAlert)-[:monitors]->(h)
  where a.status = 'firing'
optional match (h)-[:observed_as]->(ip:CanonicalIP)
optional match (ip)<-[:observed_on]-(se:SecurityEvent)
optional match (ip)<-[:indicates]-(ind:Indicator)-[:indicates]->(v:Vulnerability)
optional match (h)-[:located_at]->(s:Site)
optional match (h)<-[:member_of]-(ifc:Interface)
optional match (h)<-[:member_of]-(svc:Service)
optional match (cc:ComplianceControl)-[:controls]->(h)
optional match (cc)-[:satisfies]->(fw:Framework)
return h, collect(distinct a) as alerts,
       collect(distinct se) as events,
       collect(distinct v) as vulnerabilities,
       collect(distinct ind) as indicators,
       collect(distinct cc) as controls,
       collect(distinct fw) as frameworks,
       collect(distinct s) as sites,
       collect(distinct ifc) as interfaces,
       collect(distinct svc) as services

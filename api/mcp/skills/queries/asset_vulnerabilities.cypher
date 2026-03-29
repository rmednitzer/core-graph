match (h:Host {canonical_key: $canonical_key})
optional match (h)-[:observed_as]->(ip:CanonicalIP)
optional match (ip)<-[:indicates]-(ind:Indicator)-[:indicates]->(v:Vulnerability)
optional match (v)<-[:mitigates]-(patch:Indicator)
return v.cve_id as cve_id,
       v.severity as severity,
       ind.first_seen as first_seen,
       ind.last_seen as last_seen,
       patch is not null as patch_exists

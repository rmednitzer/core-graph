match (h:Host {canonical_key: $canonical_key})
optional match (h)-[:observed_as]->(ip:CanonicalIP)
optional match (ip)<-[:observed_on]-(se:SecurityEvent)
  where se.time > toString(localdatetime() - duration('PT' + toString($hours_back) + 'H'))
return se.event_id as event_id,
       se.category as event_type,
       se.severity as severity,
       se.source as source_system,
       se.time as timestamp
order by se.time desc

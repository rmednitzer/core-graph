match (p:Principal {principal_id: $principal_id})
optional match (p)-[:actor_in]->(se:SecurityEvent)
  where se.time > $time_threshold
return se.event_id as event_id,
       se.category as event_type,
       se.severity as severity,
       se.source as source_system,
       se.time as timestamp
order by se.time desc

match (h:Host {canonical_key: $canonical_key})
match (a:MonitoringAlert)-[:monitors]->(h)
where a.status = 'firing'
return a.alertname as alertname,
       a.severity as severity,
       a.status as status,
       a.instance as instance,
       a.starts_at as starts_at,
       a.fingerprint as fingerprint
order by a.severity desc, a.starts_at desc
limit $limit

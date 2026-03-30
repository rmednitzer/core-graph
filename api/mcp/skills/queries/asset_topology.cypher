match (h:Host {canonical_key: $canonical_key})
optional match (h)<-[:member_of]-(ifc:Interface)
optional match (ifc)-[:connects_to]-(net:Network)
optional match (h)-[:located_at]->(s:Site)
optional match (h)<-[:member_of]-(svc:Service)
optional match (h)-[:hosted_on]->(parent:Host)
return h, collect(distinct ifc) as interfaces,
       collect(distinct net) as networks,
       collect(distinct s) as sites,
       collect(distinct svc) as services,
       collect(distinct parent) as parent_hosts

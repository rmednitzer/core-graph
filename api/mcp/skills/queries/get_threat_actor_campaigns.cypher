match (ta:ThreatActor {name: $name})-[r:attributed_to]-(c:Campaign) return ta, r, c

match (v) where id(v) = $entity_id
match (v)-[edges*1..__DEPTH__]-(neighbour)
return id(v) as anchor_id,
       id(neighbour) as neighbour_id,
       labels(neighbour) as neighbour_labels,
       neighbour.canonical_key as canonical_key,
       neighbour.tlp_level as tlp_level,
       length(edges) as hops

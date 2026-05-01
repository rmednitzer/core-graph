match (a) where id(a) = $source_id
match (b) where id(b) = $target_id
match path = (a)-[edges*1..__MAX_HOPS__]-(b)
with path,
     reduce(p = 1.0, e in edges | p * coalesce(e.confidence, 0.5)) as path_confidence,
     length(path) as hops
return [n in nodes(path) | id(n)] as node_ids,
       [r in relationships(path) | type(r)] as edge_types,
       path_confidence,
       hops,
       path_confidence * exp(-0.25 * hops) as path_score
order by path_score desc
limit 25

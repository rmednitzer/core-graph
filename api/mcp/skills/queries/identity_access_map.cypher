match (p:Principal {principal_id: $principal_id})
optional match (p)-[:has_role]->(r:Role)
optional match (r)-[:grants]->(perm:Permission)
optional match (p)-[:member_of]->(g:Group)
optional match (g)-[:has_role]->(gr:Role)
optional match (gr)-[:grants]->(gperm:Permission)
return p.username as username,
       p.last_login as last_active,
       collect(distinct r.role_name) as direct_roles,
       collect(distinct perm.name) as direct_permissions,
       collect(distinct g.name) as groups,
       collect(distinct gr.role_name) as inherited_roles,
       collect(distinct gperm.name) as inherited_permissions

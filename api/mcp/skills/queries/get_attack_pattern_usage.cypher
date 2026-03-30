match (a:AttackPattern {name: $name})-[r:uses]-(n) return a, r, n

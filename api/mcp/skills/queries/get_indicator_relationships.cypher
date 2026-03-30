match (i:Indicator {value: $value})-[r]-(n) return i, r, n

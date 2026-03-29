-- schema/seed/stix-vocabularies.sql
-- STIX 2.1 open vocabulary reference data.
-- Source: OASIS STIX 2.1 specification (vocabulary names and values only).
-- Idempotent: uses ON CONFLICT DO NOTHING.

create table if not exists stix_vocabularies (
    vocabulary  text not null,
    value       text not null,
    description text,
    primary key (vocabulary, value)
);

-- attack-motivation-ov
insert into stix_vocabularies (vocabulary, value) values
    ('attack-motivation-ov', 'accidental'),
    ('attack-motivation-ov', 'coercion'),
    ('attack-motivation-ov', 'dominance'),
    ('attack-motivation-ov', 'ideology'),
    ('attack-motivation-ov', 'notoriety'),
    ('attack-motivation-ov', 'organizational-gain'),
    ('attack-motivation-ov', 'personal-gain'),
    ('attack-motivation-ov', 'personal-satisfaction'),
    ('attack-motivation-ov', 'revenge'),
    ('attack-motivation-ov', 'unpredictable')
on conflict (vocabulary, value) do nothing;

-- attack-resource-level-ov
insert into stix_vocabularies (vocabulary, value) values
    ('attack-resource-level-ov', 'individual'),
    ('attack-resource-level-ov', 'club'),
    ('attack-resource-level-ov', 'contest'),
    ('attack-resource-level-ov', 'team'),
    ('attack-resource-level-ov', 'organization'),
    ('attack-resource-level-ov', 'government')
on conflict (vocabulary, value) do nothing;

-- identity-class-ov
insert into stix_vocabularies (vocabulary, value) values
    ('identity-class-ov', 'individual'),
    ('identity-class-ov', 'group'),
    ('identity-class-ov', 'system'),
    ('identity-class-ov', 'organization'),
    ('identity-class-ov', 'class'),
    ('identity-class-ov', 'unknown')
on conflict (vocabulary, value) do nothing;

-- indicator-type-ov
insert into stix_vocabularies (vocabulary, value) values
    ('indicator-type-ov', 'anomalous-activity'),
    ('indicator-type-ov', 'anonymization'),
    ('indicator-type-ov', 'benign'),
    ('indicator-type-ov', 'compromised'),
    ('indicator-type-ov', 'malicious-activity'),
    ('indicator-type-ov', 'attribution'),
    ('indicator-type-ov', 'unknown')
on conflict (vocabulary, value) do nothing;

-- industry-sector-ov
insert into stix_vocabularies (vocabulary, value) values
    ('industry-sector-ov', 'agriculture'),
    ('industry-sector-ov', 'aerospace'),
    ('industry-sector-ov', 'automotive'),
    ('industry-sector-ov', 'chemical'),
    ('industry-sector-ov', 'commercial'),
    ('industry-sector-ov', 'communications'),
    ('industry-sector-ov', 'construction'),
    ('industry-sector-ov', 'defense'),
    ('industry-sector-ov', 'education'),
    ('industry-sector-ov', 'energy'),
    ('industry-sector-ov', 'entertainment'),
    ('industry-sector-ov', 'financial-services'),
    ('industry-sector-ov', 'government-national'),
    ('industry-sector-ov', 'government-regional'),
    ('industry-sector-ov', 'government-local'),
    ('industry-sector-ov', 'government-public-services'),
    ('industry-sector-ov', 'healthcare'),
    ('industry-sector-ov', 'hospitality-leisure'),
    ('industry-sector-ov', 'infrastructure'),
    ('industry-sector-ov', 'insurance'),
    ('industry-sector-ov', 'manufacturing'),
    ('industry-sector-ov', 'mining'),
    ('industry-sector-ov', 'non-profit'),
    ('industry-sector-ov', 'pharmaceuticals'),
    ('industry-sector-ov', 'retail'),
    ('industry-sector-ov', 'technology'),
    ('industry-sector-ov', 'telecommunications'),
    ('industry-sector-ov', 'transportation'),
    ('industry-sector-ov', 'utilities')
on conflict (vocabulary, value) do nothing;

-- malware-type-ov
insert into stix_vocabularies (vocabulary, value) values
    ('malware-type-ov', 'adware'),
    ('malware-type-ov', 'backdoor'),
    ('malware-type-ov', 'bot'),
    ('malware-type-ov', 'bootkit'),
    ('malware-type-ov', 'ddos'),
    ('malware-type-ov', 'downloader'),
    ('malware-type-ov', 'dropper'),
    ('malware-type-ov', 'exploit-kit'),
    ('malware-type-ov', 'keylogger'),
    ('malware-type-ov', 'ransomware'),
    ('malware-type-ov', 'remote-access-trojan'),
    ('malware-type-ov', 'resource-exploitation'),
    ('malware-type-ov', 'rogue-security-software'),
    ('malware-type-ov', 'rootkit'),
    ('malware-type-ov', 'screen-capture'),
    ('malware-type-ov', 'spyware'),
    ('malware-type-ov', 'trojan'),
    ('malware-type-ov', 'unknown'),
    ('malware-type-ov', 'virus'),
    ('malware-type-ov', 'webshell'),
    ('malware-type-ov', 'wiper'),
    ('malware-type-ov', 'worm')
on conflict (vocabulary, value) do nothing;

-- report-type-ov
insert into stix_vocabularies (vocabulary, value) values
    ('report-type-ov', 'attack-pattern'),
    ('report-type-ov', 'campaign'),
    ('report-type-ov', 'identity'),
    ('report-type-ov', 'indicator'),
    ('report-type-ov', 'intrusion-set'),
    ('report-type-ov', 'malware'),
    ('report-type-ov', 'observed-data'),
    ('report-type-ov', 'threat-actor'),
    ('report-type-ov', 'threat-report'),
    ('report-type-ov', 'tool'),
    ('report-type-ov', 'vulnerability')
on conflict (vocabulary, value) do nothing;

-- threat-actor-type-ov
insert into stix_vocabularies (vocabulary, value) values
    ('threat-actor-type-ov', 'activist'),
    ('threat-actor-type-ov', 'competitor'),
    ('threat-actor-type-ov', 'crime-syndicate'),
    ('threat-actor-type-ov', 'criminal'),
    ('threat-actor-type-ov', 'hacker'),
    ('threat-actor-type-ov', 'insider-accidental'),
    ('threat-actor-type-ov', 'insider-disgruntled'),
    ('threat-actor-type-ov', 'nation-state'),
    ('threat-actor-type-ov', 'sensationalist'),
    ('threat-actor-type-ov', 'spy'),
    ('threat-actor-type-ov', 'terrorist'),
    ('threat-actor-type-ov', 'unknown')
on conflict (vocabulary, value) do nothing;

-- threat-actor-sophistication-ov
insert into stix_vocabularies (vocabulary, value) values
    ('threat-actor-sophistication-ov', 'none'),
    ('threat-actor-sophistication-ov', 'minimal'),
    ('threat-actor-sophistication-ov', 'intermediate'),
    ('threat-actor-sophistication-ov', 'advanced'),
    ('threat-actor-sophistication-ov', 'expert'),
    ('threat-actor-sophistication-ov', 'innovator'),
    ('threat-actor-sophistication-ov', 'strategic')
on conflict (vocabulary, value) do nothing;

-- tool-type-ov
insert into stix_vocabularies (vocabulary, value) values
    ('tool-type-ov', 'denial-of-service'),
    ('tool-type-ov', 'exploitation'),
    ('tool-type-ov', 'information-gathering'),
    ('tool-type-ov', 'network-capture'),
    ('tool-type-ov', 'credential-exploitation'),
    ('tool-type-ov', 'remote-access'),
    ('tool-type-ov', 'vulnerability-scanning'),
    ('tool-type-ov', 'unknown')
on conflict (vocabulary, value) do nothing;

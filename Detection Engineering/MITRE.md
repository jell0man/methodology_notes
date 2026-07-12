The following are MITRE tools that will support detection tasks.
# MITRE ATT&CK
[MITRE ATT&CK](https://attack.mitre.org/) - knowledge base of TTPs.
[Enterprise matrix](https://attack.mitre.org/matrices/enterprise/), [Mobile matrix](https://attack.mitre.org/matrices/mobile/) , [ICS matrix](https://attack.mitre.org/matrices/ics/)

TTPs
	`Tactic` - overall objective. IA, EXE, CA, etc...
	`Technique` - the method. ie: LSASS dumping is a method of CA. 
	`Procedure` - real world implementation by actor, tool, etc.
### Accessing ATT&CK Data Programmatically
**Some Definitions:**
- **STIX** (Structured Threat Information Expression) — a data model and language for representing cyber threat intelligence (CTI) in a standardized way.
- **TAXII** (Trusted Automated eXchange of Intelligence Information) — a transport mechanism for sharing intelligence between systems.

The [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) repository publishes each ATT&CK domain as a STIX 2.1 bundle. ATT&CK maps its concepts onto STIX objects and custom object types, allowing ATT&CK to be queried as structured graph data.

Because ATT&CK is published as [structured STIX 2.1 data](https://mitre-attack.github.io/attack-data-model/schemas/), it can be queried programmatically. The [STIX Domain Objects](https://mitre-attack.github.io/attack-data-model/schemas/) documentation defines the schemas used by the ATT&CK Data Model.
### Interacting with ATT&CK over `attackcti`
How to access ATTA&CK programmatically? [attackcti](https://attackcti.com/intro.html) library!
```bash
# Setup
pip install attackcti requests taxii2-client 

# Inspect main methods exposed by attackcti
python3 -c "from attackcti import attack_client; c=attack_client(); print([x for x in dir(c) if not x.startswith('_')])"
```

What does each function do?

|Function|Purpose|
|---|---|
|[attack_client()](https://attackcti.com/playground/8-Lookup_Functions.html#initialize-att-ck-client-variable)|Initializes the ATT&CK client and connects to the MITRE ATT&CK STIX/TAXII server.|
|[get_enterprise()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html#collect-enterprise-att-ck)|Retrieves all Enterprise ATT&CK objects at once (techniques, groups, malware, mitigations, relationships, tactics, etc.) as a keyed dictionary.|
|[get_enterprise_techniques()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html?highlight=get_enterprise_techniques#collect-enterprise-techniques)|Retrieves all Enterprise techniques and sub-techniques (`attack-pattern`).|
|[get_enterprise_tactics()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html#collect-enterprise-tactics)|Retrieves Enterprise tactics such as Execution, Persistence, Credential Access, etc.|
|[get_enterprise_groups()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html?highlight=get_enterprise_groups#collect-enterprise-groups)|Retrieves adversary groups (intrusion sets) in Enterprise ATT&CK.|
|[get_enterprise_malware()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html?highlight=get_enterprise_malware#collect-enterprise-malware)|Retrieves malware objects associated with Enterprise ATT&CK.|
|[get_enterprise_mitigations()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html?highlight=get_enterprise_mitigations#collect-enterprise-mitigations)|Retrieves mitigation objects (`course-of-action`) mapped to techniques.|
|[get_enterprise_relationships()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html?highlight=get_enterprise_relationships#collect-enterprise-relationships)|Retrieves all STIX relationship objects in Enterprise ATT&CK (e.g., `uses`, `detects`, `mitigates`) linking groups, malware, techniques, and data components.|
|[get_enterprise_data_sources()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html#collect-enterprise-data-sources)|Retrieves data source objects scoped to Enterprise ATT&CK.|
|[get_techniques()](https://attackcti.com/playground/1-Collect_All_Functions.html#get-all-techniques)|Retrieves all techniques across all ATT&CK matrices at once.|
|[get_groups()](https://attackcti.com/playground/1-Collect_All_Functions.html#get-all-groups)|Retrieves all groups across all ATT&CK matrices at once.|
|[get_software()](https://attackcti.com/playground/1-Collect_All_Functions.html#get-all-software)|Retrieves all software (malware and tools) across all ATT&CK matrices.|
|[get_relationships()](https://attackcti.com/playground/1-Collect_All_Functions.html#get-all-relationships)|Retrieves all STIX relationship objects across all ATT&CK matrices.|
|[get_data_sources()](https://attackcti.com/playground/1-Collect_All_Functions.html?highlight=get_data_sources#get-all-data-sources)|Retrieves all ATT&CK data source objects.|
|[get_data_components()](https://attackcti.com/playground/1-Collect_All_Functions.html?highlight=get_data_components#get-all-data-components)|Retrieves all ATT&CK data component objects.|
|[get_campaigns()](https://attackcti.com/playground/9-Explore_Campaigns.html?highlight=get_campaigns#get-all-campaigns)|Retrieves ATT&CK campaign objects describing adversary operations.|
|[get_campaign_by_alias()](https://attackcti.com/playground/9-Explore_Campaigns.html?highlight=get_campaign_by_alias#get-campaign-by-alias)|Retrieves a campaign by alias or alternative name.|
|[get_campaigns_since_time()](https://attackcti.com/playground/9-Explore_Campaigns.html?highlight=get_campaigns_since_time#get-campaigns-since)|Retrieves campaigns updated after a specific timestamp for delta tracking.|
|[get_ics_techniques()](https://attackcti.com/playground/2-Collect_Matrix_Specific_Functions.html?highlight=get_ics_techniques#collect-ics-techniques)|Retrieves ICS ATT&CK techniques for OT and SCADA environments.|
|[export_groups_navigator_layers()](https://attackcti.com/playground/7-Export_Groups_Navigator_Layers.html?highlight=export_groups_navigator_layers#create-navigator-group-layer-files-automatic)|Exports ATT&CK group mappings into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer format.|

Some practical examples
```bash
# List all tactic names
python3 -c "from attackcti import attack_client; c=attack_client(); print(sorted(set(t['name'] for t in c.get_tactics())))"

# List tactic shortnames
python3 -c "from attackcti import attack_client; c=attack_client(); print(sorted(set(t.get('x_mitre_shortname') for t in c.get_tactics() if t.get('x_mitre_shortname'))))"

# List tactic names with their ATT&CK tactic shortnames
python3 -c "from attackcti import attack_client; c=attack_client(); print(sorted((t['name'], t.get('x_mitre_shortname')) for t in c.get_tactics() if t.get('x_mitre_shortname')))"

# List only Linux Techniques
python3 -c "from attackcti import attack_client; c=attack_client(); print([(t.get('external_references',[{}])[0].get('external_id'), t['name']) for t in c.get_techniques() if 'Linux' in t.get('x_mitre_platforms',[])])"

# List only sub-techniques
python3 -c "from attackcti import attack_client; c=attack_client(); print([(t.get('external_references',[{}])[0].get('external_id'), t['name']) for t in c.get_techniques() if t.get('x_mitre_is_subtechnique')])"

# List techniques mapped to a specific tactic
python3 -c "from attackcti import attack_client; c=attack_client(); tactic='credential-access'; print([(next((r.get('external_id') for r in t.get('external_references', []) if r.get('external_id')), None), t['name']) for t in c.get_techniques() if any(k.get('phase_name') == tactic for k in t.get('kill_chain_phases', []))])"

# Techniques used by Mimikatz (S0002)
python3 -c "from attackcti import attack_client; c=attack_client.from_attack_stix_data(); s=c.get_object_by_attack_id('tool','S0002'); print([t['name'] for t in c.get_techniques_used_by_software(s)])"

# Techniques used by APT29
python3 -c "from attackcti import attack_client; c=attack_client.from_attack_stix_data(); g=c.get_object_by_attack_id('intrusion-set','G0016'); print([t['name'] for t in c.get_techniques_used_by_group(g)])"
```
### Detection Strategies and Analytics


# MITRE Cyber Analytics Repository (CAR)
# MITRE D3FEND
# ATT&CK Navigator
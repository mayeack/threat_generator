TA-threat_gen
=============

Technology Add-on that parses ThreatGen APT-simulation events and exposes the
entity fields Splunk Enterprise Security Exposure Analytics needs for its
streaming entity discovery / Validate step.

Supported sourcetypes and source routing
----------------------------------------

ThreatGen emits single-line JSON events over HTTP Event Collector (HEC) with a
distinct source per event family. This TA defines [source::threatgen:*]
stanzas that pin the correct sourcetype and set KV_MODE = json:

  source = threatgen:wineventlog  -> sourcetype = WinEventLog:Security
  source = threatgen:sysmon       -> sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  source = threatgen:linux_secure -> sourcetype = linux_secure
  source = threatgen:stream_dns   -> sourcetype = stream:dns
  source = threatgen:stream_http  -> sourcetype = stream:http
  source = threatgen:cisco_asa    -> sourcetype = cisco:asa

Note: ThreatGen also ships a default `hec.sourcetype_map` in
default_config.yaml that sends OOTB Splunk sourcetypes directly on the HEC
wire (e.g., `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`). That
default alone closes the sourcetype-naming gap for HEC-only deployments,
but this TA is still required to:

  * apply KV_MODE = json so search-time field extraction works on the
    ThreatGen single-line JSON payload, and
  * run the index-time entity-field transforms (nt_host, ip, user_id, mac)
    that Splunk ES Exposure Analytics streaming validation depends on.

Index-time operations (important)
---------------------------------

This TA ships index-time field extractions so Exposure Analytics streaming
validation (which relies on tstats against indexed fields, not search-time KV)
can see the key entity fields on every event:

  * default/transforms.conf declares threatgen_nt_host, threatgen_ip,
    threatgen_user_id, threatgen_mac with WRITE_META = true.
  * default/fields.conf declares nt_host, ip, user_id, mac with INDEXED = true.
  * default/props.conf wires them via
    TRANSFORMS-threatgen_entity_fields on every [source::threatgen:*] stanza.

Because these operations run at index time, the TA must be installed on BOTH
the search-head tier and the indexer tier. On Splunk Cloud (Victoria) the
Admin Config Service (ACS) self-service install handles both tiers; on Splunk
Cloud Classic, index-time configs require a Splunk Cloud Ops support ticket.

Install on Splunk Cloud (Victoria)
----------------------------------

1. Build the package from the repository root:
     ./scripts/package_ta.sh
   This produces dist/TA-threat_gen-<version>.tgz.

2. Validate with AppInspect (cloud tags):
     ./scripts/validate_ta.sh dist/TA-threat_gen-<version>.tgz

3. Upload via Splunk Web: Settings -> Apps -> Install app from file, and
   select the .tgz. Alternatively, use ACS:
     curl -X POST -H "Authorization: Bearer $ACS_TOKEN" \
       -H "ACS-Legal-Ack: Y" \
       --data-binary @dist/TA-threat_gen-<version>.tgz \
       "https://admin.splunk.com/<stack>/adminconfig/v2/apps/victoria"

4. After install, confirm the indexer tier picked up the index-time configs:
     | tstats count where index=threat_gen by nt_host, sourcetype
   A non-zero count per sourcetype means Exposure Analytics will see the
   key values and Validate should clear.

Install on-prem
---------------

Copy the folder to $SPLUNK_HOME/etc/apps/TA-threat_gen on every search head
and indexer (or distribute via a deployment server). On a Universal Forwarder
that tails the ThreatGen log files, create local/inputs.conf with monitor
stanzas for each sourcetype, for example:

  [monitor:///path/to/threatgen/logs/cisco_asa.log]
  disabled = false
  index = threat_gen
  sourcetype = cisco:asa
  source = threatgen:cisco_asa

Contents
--------

  default/app.conf         App metadata (cloud-compliant)
  default/props.conf       [source::threatgen:*] parsing + KV_MODE=json
  default/transforms.conf  Index-time entity-field extractions
  default/fields.conf      INDEXED=true declarations for nt_host/ip/user_id/mac
  default/inputs.conf      Empty (HEC ingestion; no default monitors)
  metadata/default.meta    System export of props/transforms/fields

Support
-------

Issues: https://github.com/splunk/ThreatGenerator

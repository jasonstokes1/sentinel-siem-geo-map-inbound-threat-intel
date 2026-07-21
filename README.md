# 🚨 Microsoft Sentinel SIEM — Geo Map 4: Allowed Inbound Flows from Threat-Intel IPs

Part of a broader **Microsoft Sentinel SIEM** portfolio series. This workbook correlates two independent data sources — accepted network traffic and a live threat-intelligence feed — to answer the question that matters most: **not just who's out there, but who got in.**

## Platforms and Languages Leveraged

- Microsoft Sentinel / Log Analytics Workspace
- Azure Network Watcher (`NTANetAnalytics` — VNet flow log analytics table)
- Microsoft Sentinel Threat Intelligence (`ThreatIntelIndicators` table)
- Kusto Query Language (KQL) — including `let` statements and an inner `join`
- Azure Monitor Workbooks (native `geo_info_from_ip_address()` geolocation, MaxMind GeoLite2 data)

## Scenario

A threat-intel feed flagging an IP as malicious only tells you it *tried* to reach you, or that it's known-bad somewhere in the world — it doesn't tell you whether your own defenses actually stopped it. This workbook closes that gap by joining your **live TI watchlist** against your **own accepted-traffic logs**. A result here isn't a theoretical risk; it's a known-malicious IP whose inbound traffic your network let through.

## What the Workbook Does

- **Time range parameter** — same pill selector pattern, defaulting to 30 days.
- **Bubble map** — plots each threat-intel-matched source IP that got through, geolocated. Bubble **size** = total allowed inbound flows; **color** = bytes received, so a bubble that's both large and red-hot represents high-frequency, high-volume contact from a confirmed-hostile source.
- **Companion table** — the same matched sources ranked by allowed flows and target count, with threat-intel context (confidence score, threat type, tags) carried alongside the traffic data, plus conditional formatting (red heat) on `BytesIn` and `AllowedFlows` for fast visual triage.

## Query Logic

This is the most involved query in the series — it builds a lookup table, then joins it against live traffic:

**Step 1 — Build the TI watchlist (`let TI_IPs =`)**
- Pulls from `ThreatIntelIndicators` over the last 30 days.
- `summarize arg_max(TimeGenerated, *) by Id` — deduplicates indicators that have been re-ingested multiple times, keeping only the most recent version of each.
- `IsActive == true` and an unexpired `ValidUntil` — filters to indicators still considered current.
- `ObservableKey in (...)` — restricts to indicators describing an IP address (covering the different STIX observable key formats a feed might use).
- Extracts a normalized `ThreatType`, `Confidence`, and `Tags` per indicator.

**Step 2 — Match against real traffic**
- Queries `NTANetAnalytics` for `SubType == "FlowLog"` with `AllowedInFlows > 0` — flows that were let in, not blocked.
- `join kind=inner TI_IPs on $left.SrcIp == $right.TI_IP` — keeps only traffic whose source IP appears on the TI watchlist. This inner join is what turns "IPs we know are bad" and "traffic we accepted" into "bad traffic we actually accepted."

**Step 3 — Geo-enrich and aggregate**
- `geo_info_from_ip_address()` enriches the matched source; rows without a resolved city + country are dropped.
- Aggregated per source IP: total allowed/denied flows, bytes received, distinct internal targets reached, ports used, max confidence score, and the set of threat types associated with that IP.

```kql
let TI_IPs =
    ThreatIntelIndicators
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by Id  // dedup re-ingested indicators
    | where IsActive == true
    | where isempty(ValidUntil) or ValidUntil > now()  // not expired
    | where ObservableKey in ("ipv4-addr:value",
                               "network-traffic:src_ref.value",
                               "network-traffic:dst_ref.value")
    | extend ThreatType = tostring(Data.indicator_types[0])
    | project TI_IP = ObservableValue, Confidence, ThreatType, Tags
    | where isnotempty(TI_IP);
NTANetAnalytics
| where TimeGenerated {TimeRange}
| where SubType == "FlowLog"
| where AllowedInFlows > 0  // it got IN - not denied
| where isnotempty(SrcIp)
| join kind=inner TI_IPs on $left.SrcIp == $right.TI_IP
| extend geo = geo_info_from_ip_address(SrcIp)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         State     = tostring(geo.state),
         City      = tostring(geo.city)
| where isnotempty(City) and isnotempty(Country)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize AllowedFlows  = sum(AllowedInFlows),
            DeniedFlows   = sum(DeniedInFlows),
            BytesIn       = sum(BytesSrcToDest),
            Targets       = dcount(DestIp),
            Ports         = make_set(DestPort, 15),
            MaxConfidence = max(Confidence),
            ThreatTypes   = make_set(ThreatType, 10)
         by SrcIp, Country, State, City, Latitude, Longitude
| extend MapLabel = strcat(SrcIp, " (", City, ", ", State, ", ", Country, ") - ", AllowedFlows, " allowed, ", Targets, " targets")
| project Latitude, Longitude, MapLabel, AllowedFlows, DeniedFlows, BytesIn, Targets, Ports, MaxConfidence, ThreatTypes, SrcIp, Country, State, City
| order by AllowedFlows desc, Targets desc
```

> Geo data (MaxMind GeoLite2) is approximate — read the map as regions, not pinpoints.

## How to Use

1. Open **Microsoft Sentinel** → **Workbooks** → **Add workbook** → **Advanced Editor** (`</>` icon).
2. Delete the placeholder JSON and paste in the contents of [`workbook.json`](./workbook.json).
3. Update `crossComponentResources` and the `context.ownerId` field to point at your own Log Analytics workspace resource ID.
4. Confirm both **Threat Intelligence** (Sentinel content hub or a connected TI feed) and **Network Watcher Traffic Analytics** are enabled — this workbook depends on both `ThreatIntelIndicators` and `NTANetAnalytics` being populated.
5. Save, then apply the workbook to your workspace.
6. Adjust the **Time range** pill to control the lookback window for both the map and the table.

## Repository Contents

| File | Description |
|---|---|
| [`workbook.json`](./workbook.json) | Full Azure Monitor Workbook definition — import directly into Sentinel |

## About

Built as a lab exercise against a Log Analytics workspace (`LAW-Cyber-Range`). Part of a growing Microsoft Sentinel SIEM workbook series covering inbound authentication, outbound connections, data exfiltration indicators, inbound threat intel correlation, and threat intelligence ingestion (manual + Microsoft feed).

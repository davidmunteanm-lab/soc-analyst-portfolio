# Splunk SPL Cheatsheet

Quick-reference SPL queries I've used in TryHackMe rooms and would reach for in a real SOC shift. Examples assume standard log sources (Windows event logs, Sysmon, web access logs).

## Search & filter basics

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
```

Failed logon events. `EventCode=4624` is successful logon.

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by user, src_ip
| sort -count
```

Group failed logons by user and source IP, sorted descending — quick brute-force detection.

## Time-based pivots

```spl
index=main earliest=-24h@h latest=now
| timechart span=1h count by sourcetype
```

Volume of events per source over the last 24 hours, hourly. Useful for spotting anomalies — a quiet log source going silent, or a noisy one spiking.

```spl
index=main user=alice earliest=-7d
| timechart span=1h count
```

Activity timeline for a single user across the last week.

## Detection patterns

### Brute force (failed → success)

```spl
index=main sourcetype=WinEventLog:Security
| transaction user startswith=EventCode=4625 endswith=EventCode=4624 maxspan=10m
| where eventcount > 5
| table user, src_ip, eventcount, duration
```

Catches users with 5+ failures followed by a success in under 10 minutes.

### Suspicious PowerShell

```spl
index=main sourcetype=WinEventLog:* EventCode=4104
| search ScriptBlockText="*-EncodedCommand*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*IEX*"
| table _time, host, user, ScriptBlockText
```

PowerShell ScriptBlock logs containing common red-team patterns.

### Rare process execution

```spl
index=main sourcetype=sysmon EventCode=1
| stats count by Image, ParentImage
| where count < 5
| sort count
```

Surfaces processes that have rarely (or never) been seen on the network — possible LOLBins or malware.

## Useful field manipulations

```spl
| rex field=_raw "user=(?<extracted_user>\w+)"
```

Extract a custom field with regex when it's not already parsed.

```spl
| eval risk_score = case(
    EventCode=4625, 1,
    EventCode=4720, 3,
    EventCode=4732, 5,
    true(), 0
  )
```

Assign weights to events for a simple scoring approach.

## Lookups & enrichment

```spl
| lookup geoip clientip OUTPUT country, city
```

Enrich IPs with geolocation (assumes a `geoip` lookup is configured).

```spl
| iplocation src_ip
| stats count by Country
| sort -count
```

Same idea using the built-in `iplocation` command — handy for spotting logons from countries you don't expect.

## Tips I keep forgetting

- `index=*` is wasteful — always scope to the index you actually need.
- `| head 10` early in a search to test before letting it run on huge data sets.
- `sourcetype=*` is similarly broad; restrict it when you can.
- `dedup` keeps the *first* event per key by default — use `sortby _time` to control which one.
- `stats count by foo` is much faster than `chart` when you don't need a visualization.

## References

- [Splunk SPL documentation](https://docs.splunk.com/Documentation/Splunk/latest/Search/GetstartedwithSearch)
- [TryHackMe — SOC Level 1 path](https://tryhackme.com/path/outline/soclevel1)
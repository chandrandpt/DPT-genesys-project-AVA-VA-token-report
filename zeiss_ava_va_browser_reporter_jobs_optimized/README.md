# Genesys AVA/VA Division Reporter - Jobs Optimized

Local browser app for historical AVA/VA division reconciliation with low Genesys Cloud API consumption.

## Run on macOS

```bash
cd /path/to/zeiss_ava_va_browser_reporter_jobs_optimized
python3 genesys_ava_va_browser_reporter.py
```

Open the local URL printed in Terminal (normally `http://127.0.0.1:8765`). No pip packages are required.

## What changed vs the synchronous-query version

### Analytics
- Uses `POST /api/v2/analytics/conversations/details/jobs` for the entire selected reporting interval.
- Applies `flowId` predicates so the job returns only conversations touching discovered VA/AVA-enabled flows.
- Packs flow IDs into large batches; if Genesys rejects a batch as too large, the app automatically splits it.
- Uses adaptive polling rather than frequent fixed polling.
- Fetches result pages using the cursor and a large requested `pageSize`.
- Deduplicates conversations by `conversationId` if more than one job/batch returns them.

### Architect metadata
- `GET /api/v2/flows` is cached locally for 6 hours.
- Individual `GET /flows/{id}` calls are only used for BOT/DIGITALBOT flows when the list response does not contain the VA/AVA flags.
- Classification remains version-aware: the exact `flowVersion` found in Analytics is used.
- Historical version capability data is cached in memory and persisted under `~/.genesys_ava_va_reporter/metadata_cache_v4.json`.
- If the observed version is the current published version, the app reuses the published-version metadata instead of making a version API call.
- If several historical versions of the same flow are needed, it attempts one version-list request before falling back to individual version requests.

### Divisions
- Flow discovery does not enumerate every organization division.
- After the Analytics job completes, the app resolves only division IDs actually found on the matched conversations.
- Resolved division names are cached for later runs.

### OAuth and HTTP
- OAuth access tokens are cached in memory until close to expiry.
- HTTP 429/5xx retries use backoff and honor Retry-After when available.
- TLS verification remains enabled and the app can use macOS keychain certificates / an optional corporate CA PEM.

## Outputs
- `flow_inventory.csv`
- `interaction_flow_matches.csv`
- `interaction_classification.csv`
- `summary_by_division.csv`
- `flow_version_capabilities.csv`
- Download-all ZIP from the browser UI

## Classification
For each matched conversation:
1. Read `flowId` and the exact `flowVersion` from Analytics Conversation Details.
2. Resolve the VA/AVA flags for that historical version.
3. If any visited version has `agenticVirtualAgentEnabled=true`, classify the interaction as AVA.
4. Otherwise, if any visited version has `virtualAgentEnabled=true`, classify it as VA.
5. Attribute the result to the conversation's `divisionIds`.
6. Estimate raw usage at 1.2 tokens for AVA and 0.5 for VA for reconciliation purposes.

## API counters
The browser displays counters including:
- Analytics jobs created
- Job status polls
- Analytics result pages
- Version API calls
- Version memory/persistent-cache hits
- Total Genesys API calls for the scan/report

These counters make it easy to compare API consumption with the earlier synchronous implementation.

## Important notes
- Use this for historical/reconciliation reporting, not real-time operational reporting.
- The OAuth client's division grants determine which conversations/flows it can see.
- Continue validating totals against official Genesys Subscription / Resource Usage data.
- The local persistent cache contains flow/version/division metadata, not OAuth secrets. Credentials remain in memory only.

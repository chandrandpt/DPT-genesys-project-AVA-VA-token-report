# Validation checklist

1. Run the same billing period that already reconciles in the previous version.
2. Confirm AVA/VA interaction counts and token totals remain identical.
3. Confirm `analytics_jobs_created` is normally 1 when the target flow list fits in one job request.
4. Review `analytics_job_status_polls`; adaptive polling should keep this low.
5. Confirm `analytics_result_pages` is normally 1 for a small billing-period result set.
6. Run the same report again without restarting the app: version API calls should drop due to memory cache.
7. Restart the app and rerun: historical version API calls should still be reduced due to persistent metadata cache.
8. Confirm division names resolve correctly while only matched division IDs are queried.
9. Compare `genesys_api_calls_this_report` against the synchronous v3 result.

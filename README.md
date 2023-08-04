# Splunk Detection Content
This repository is used to create, manage, and automatically document Splunk Enterprise Security (ES) detection content and data sources.


    ```code .```

## Update Splunk Correlation Search Detection Docs
1. Open Splunk ES Search and run the following query (time range doesn't matter):

```
| rest splunk_server=local count=0 /services/saved/searches
| where match('action.correlationsearch.enabled', "1|[Tt]|[Tt][Rr][Uu][Ee]")
| search disabled=0 NOT description="[DRAFT]*"
| rex field=search "(?<=index=)(?<index>[^\s]+)"
| rex field=search "(?<=datamodel:)(?<datamodel>[^\s]+)"
| rex field=search "(?<=datamodel=)(?<datamodel2>[^\s]+)"
| sort - updated_time
| table updated_time, updated, title, index, datamodel, product, action.correlationsearch.label, author, disabled, description, search, dispatch.earliest_time, dispatch.latest_time, cron_schedule, action.notable.param.rule_title, action.notable.param.rule_description, action.notable.param.security_domain, action.notable.param.severity, action.notable.param.drilldown_name, action.notable.param.drilldown_search, action.risk.param._risk_object_type, action.risk.param._risk_score, action.risk.param._risk_object
```

2. Export results to a JSON file named “correlation_searches”
3. Copy/paste the file into your local /inputs folder of this repository overwriting the old file
4. Run the bin/essearch-to-md.py Python script
5. Copy results from the /docs/correlation_searches.md file. Edit the [ES Correlation Searches Confluence page] (URL) and paste results (paste and match style) overwriting content in the righthand pane. Publish the page.
5. Copy results from the /docs/correlation_searches_recent.md file. Edit the [Detection Content and Data Source Updates Confluence page](URL) and paste results (paste and match style) overwriting content between the "Detection Content" heading and the "Data Sources" heading. Publish the page.

## Update Splunk Products/Data Sources
1. Open Splunk ES Search and run the following query (time range doesn't matter):

```
| tstats count where index=* by sourcetype
| eval sourcetype_details="```index=".Index." sourcetype=".sourcetype."``` - ".description
| stats values(Index) as indexes values(product_description) as product_description values(attack_datasource) as attack_datasources values(criticality) as criticality values(sourcetype_details) as sourcetype_details values(normalized) as normalized values(security_logs) as security_logs by product
| eval normalized=if(match(normalized,"Yes") AND match(normalized,"No") OR match(normalized,"Yes") AND match(normalized,"Partially") OR match(normalized,"Partially"), "Partial", normalized)
| fillnull sourcetype_details value=N/A
| fillnull criticality value="Not determined"
| fillnull normalized value="Not determined"
| fillnull security_logs value="Unknown"
```

2. Export results to a JSON file named “product_data_sources”
3. Copy/paste the file into your local /inputs folder of this repository overwriting the old file
4. Run the bin/esproducts-to-md.py Python script
5. Copy results from the /docs/es_data_sources.md file. Paste the results to Confluence page.

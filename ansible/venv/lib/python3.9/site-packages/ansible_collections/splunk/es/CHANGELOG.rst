===================================================
Splunk Enterprise Security Collection Release Notes
===================================================

.. contents:: Topics


v2.1.0
======

Minor Changes
-------------

- splunk_adaptive_response_notable_events - Manage Adaptive Responses notable events resource module
- splunk_correlation_searches - Splunk Enterprise Security Correlation searches resource module
- splunk_data_inputs_monitor - Splunk Data Inputs of type Monitor resource module
- splunk_data_inputs_network - Manage Splunk Data Inputs of type TCP or UDP resource module

v2.0.0
======

Major Changes
-------------

- Minimum required ansible.netcommon version is 2.5.1.
- Updated base plugin references to ansible.netcommon.

Bugfixes
--------

- Fix ansible test sanity failures and fix flake8 issues.

v1.0.2
======

Release Summary
---------------

- Re-releasing the 1.0.2 with updated galaxy file

v1.0.1
======

Release Summary
---------------

- Releasing 1.0.1 with updated changelog.

v1.0.0
======

New Modules
-----------

- splunk.es.adaptive_response_notable_event - Manage Splunk Enterprise Security Notable Event Adaptive Responses
- splunk.es.correlation_search - Manage Splunk Enterprise Security Correlation Searches
- splunk.es.correlation_search_info - Manage Splunk Enterprise Security Correlation Searches
- splunk.es.data_input_monitor - Manage Splunk Data Inputs of type Monitor
- splunk.es.data_input_network - Manage Splunk Data Inputs of type TCP or UDP

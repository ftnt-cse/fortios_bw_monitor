In very rare cases, there might be a situation where SNMP bandwidth collection is not suitable. In this case the requirement is to collect specific interfaces bandwidth grouped by their VDOM membership. 
FortiGate Collects bandwidth information each few seconds and stores it locally for a minimum period of an hour. It is far more efficient to collect the computed values for an hour instead of making an SNMP probe each min to fetch the counters and do the calculation each time.
This method provides the ability to apply statistical functions to the data before the event reaches FortiSIEM

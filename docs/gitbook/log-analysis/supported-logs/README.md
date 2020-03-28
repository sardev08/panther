# Supported Logs

Panther can analyze all types of data generated from clouds, endpoints, network devices, or applications. Parsers for each log you wish to analyze are required to enable rule processing. To request support for new log types, please open a [Github issue](https://github.com/panther-labs/panther/issues) or develop your own [with our guide](writing-parsers.md)!

## Log Categories

One monitoring strategy is to collect data in layers, from most broad reaching to most specific.

To understand the structure of these logs, click through to the pages below:

1. Cloud
  1. [AWS](./aws.md) (CloudTrail, S3 Access, AuroraMySQL, GuardDuty)
2. Network
  1. [AWS VPC Flow Logs](./aws.md#aws.vpcflow)
  2. [AWS ALB](./aws.md#aws.alb)
  3. _Suricata (coming soon!)_
  4. _Zeek (coming soon!)_
2. Host
  1. [Osquery](./osquery.md)
  2. [OSSEC EventInfo](./ossec.md)
  3. [Syslog](./syslog.md)
    1. _Fluentd Syslog (coming soon!)_
3. Application
  1. [NGINX Access](./nginx.md)
  2. _Okta (coming soon!)_
  3. _OneLogin (coming soon!)_

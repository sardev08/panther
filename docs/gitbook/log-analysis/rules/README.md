# Rules

Panther enables easy aggregation, normalization, analysis, and storage of security logs. **Rules** are Python functions used to identify suspicious activity and generate alerts for your team to triage.

Each rule includes:

- A `rule` function with an `event` argument and a `return` statement - `True` if the rule should send an alert, or `False` if not
- A `dedup` function to control how alerts are grouped together
- A `title` function for the message shown in the alert
- Metadata containing context for triage
- An association with a specific Log Type

As an example, the rule below checks if unauthenticated access occurred on an S3 bucket:

```python
# A set of S3 buckets all access should be authenticated
AUTH_BUCKETS = {'example-bucket'}


def rule(event):
    if event.get('bucket') not in AUTH_BUCKETS:
        return False

    return 'requester' not in event


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Unauthenticated Access to S3 Bucket  {}'.format(event.get('bucket'))
```

- This rule will group alerts by the bucket name
- Alerts will have a title such as `Unauthenticated Access to S3 Bucket my-super-secret-data`

By default, rules are pre-installed from Panther's [open-source packs](https://github.com/panther-labs/panther-analysis) and cover baseline detections and examples across supported log types:

- AWS CIS
- AWS Best Practices
- AWS Samples (VPC, S3, CloudTrail, and more)
- Osquery CIS
- Osquery Samples

## Included Libraries

Python provides high flexibility in defining your rules, and the following libraries are available to be used in Panther's runtime environment:

| Package          | Version   | Description                 | License   |
| :--------------- | :-------- | :-------------------------- | :-------- |
| `boto3`          | `1.10.46` | AWS SDK for Python          | Apache v2 |
| `policyuniverse` | `1.3.2.1` | Parse AWS ARNs and Policies | Apache v2 |
| `requests`       | `2.22.0`  | Easy HTTP Requests          | Apache v2 |

If you would like to request a new library, [please file a feature request](https://github.com/panther-labs/panther/issues/new/choose)!

## Writing Rules

{% hint style="info" %}
Coming soon!
{% endhint %}

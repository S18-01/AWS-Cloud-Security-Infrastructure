import hashlib
import json
import logging
import os
from urllib.parse import unquote_plus

from detector import detect_findings

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
MAX_LOG_BYTES = 1024 * 1024


def process_notification(notification, s3, dynamodb, bucket, table):
    if notification.get("Event") == "s3:TestEvent":
        return

    for record in notification["Records"]:
        source = record["s3"]
        key = unquote_plus(source["object"]["key"])
        if (record["eventSource"] != "aws:s3" or source["bucket"]["name"] != bucket
                or not key.startswith("logs/") or not key.endswith(".json")):
            raise ValueError("Unexpected S3 log source")

        with s3.get_object(Bucket=bucket, Key=key)["Body"] as body:
            payload = body.read(MAX_LOG_BYTES + 1)
        if len(payload) > MAX_LOG_BYTES:
            raise ValueError("Log batch exceeds size limit")
        events = json.loads(payload)
        if not isinstance(events, list) or any(not isinstance(event, dict) for event in events):
            raise ValueError("Expected a JSON array of event objects")

        findings = detect_findings(events)
        for finding in findings:
            identity = json.dumps([bucket, key, finding["rule_id"], finding["source_ip"]])
            finding_id = hashlib.sha256(identity.encode()).hexdigest()
            item = {
                "finding_id": {"S": finding_id},
                "log_key": {"S": key},
                "rule_id": {"S": finding["rule_id"]},
                "severity": {"S": finding["severity"]},
                "source_ip": {"S": finding["source_ip"]},
                "failed_attempts": {"N": str(finding["failed_attempts"])},
            }
            try:
                dynamodb.put_item(TableName=table, Item=item,
                                  ConditionExpression="attribute_not_exists(finding_id)")
            except dynamodb.exceptions.ConditionalCheckFailedException:
                continue
        LOGGER.info("Processed %s events with %s findings", len(events), len(findings))


def process_batch(event, s3, dynamodb, bucket, table):
    failures = []
    for message in event["Records"]:
        try:
            process_notification(json.loads(message["body"]), s3, dynamodb, bucket, table)
        except Exception:
            LOGGER.exception("Failed SQS message %s", message["messageId"])
            failures.append({"itemIdentifier": message["messageId"]})
    return {"batchItemFailures": failures}


def lambda_handler(event, context):
    import boto3

    return process_batch(event, boto3.client("s3"), boto3.client("dynamodb"),
                         os.environ["LOG_BUCKET"], os.environ["FINDINGS_TABLE"])

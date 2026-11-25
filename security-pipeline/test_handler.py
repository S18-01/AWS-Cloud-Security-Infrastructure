import io
import json
import unittest
from unittest.mock import Mock

from generate_logs import generate_events
from handler import process_batch


class DuplicateFinding(Exception):
    pass


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.s3 = Mock()
        self.s3.get_object.side_effect = lambda **kwargs: {
            "Body": io.BytesIO(json.dumps(generate_events()).encode())
        }
        self.db = Mock()
        self.db.exceptions.ConditionalCheckFailedException = DuplicateFinding
        record = {"eventSource": "aws:s3", "s3": {
            "bucket": {"name": "demo"},
            "object": {"key": "logs%2Fdemo.json"},
        }}
        self.message = {"messageId": "valid", "body": json.dumps({"Records": [record]})}

    def process(self, *messages):
        return process_batch({"Records": messages}, self.s3, self.db, "demo", "findings")

    def test_synthetic_batch_creates_one_finding(self):
        self.assertEqual(self.process(self.message), {"batchItemFailures": []})
        self.s3.get_object.assert_called_once_with(Bucket="demo", Key="logs/demo.json")
        self.db.put_item.assert_called_once()
        item = self.db.put_item.call_args.kwargs["Item"]
        self.assertEqual(item["source_ip"], {"S": "192.0.2.10"})
        self.assertEqual(item["failed_attempts"], {"N": "5"})

    def test_duplicate_delivery(self):
        self.db.put_item.side_effect = [None, DuplicateFinding()]
        self.assertEqual(self.process(self.message, self.message), {"batchItemFailures": []})
        first, second = self.db.put_item.call_args_list
        self.assertEqual(first.kwargs["Item"]["finding_id"], second.kwargs["Item"]["finding_id"])
        self.assertEqual(second.kwargs["ConditionExpression"], "attribute_not_exists(finding_id)")

    def test_retries_only_failed_message(self):
        with self.assertLogs("handler", level="ERROR"):
            result = self.process({"messageId": "bad", "body": "invalid"}, self.message)
        self.assertEqual(result, {"batchItemFailures": [{"itemIdentifier": "bad"}]})
        self.db.put_item.assert_called_once()

    def test_ignores_s3_test_notification(self):
        result = self.process({"messageId": "test", "body": '{"Event":"s3:TestEvent"}'})
        self.assertEqual(result, {"batchItemFailures": []})
        self.s3.get_object.assert_not_called()

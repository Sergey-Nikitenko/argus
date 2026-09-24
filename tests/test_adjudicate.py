import unittest

from argus.adjudicate import parse_verdict


class TestParseVerdict(unittest.TestCase):
    def test_json(self):
        v = parse_verdict('{"verdict": "MALICIOUS", "confidence": 0.87, "reason": "encoded cradle"}')
        self.assertEqual(v["verdict"], "MALICIOUS")
        self.assertAlmostEqual(v["confidence"], 0.87)
        self.assertEqual(v["reason"], "encoded cradle")

    def test_json_lowercase_and_clamped(self):
        v = parse_verdict('{"verdict": "benign", "confidence": 1.5, "reason": ""}')
        self.assertEqual(v["verdict"], "BENIGN")
        self.assertEqual(v["confidence"], 1.0)

    def test_fallback_regex(self):
        v = parse_verdict("BENIGN - this is a deployment tool")
        self.assertEqual(v["verdict"], "BENIGN")

    def test_garbage_is_uncertain(self):
        v = parse_verdict("no idea what this is")
        self.assertEqual(v["verdict"], "UNCERTAIN")


if __name__ == "__main__":
    unittest.main()

import unittest

from argus.agent import run_agent
from argus.tools import Tool


def _lineage(image):
    return '{"image": "evil.exe", "parents": [{"image": "a.exe", "count": 1}]}'


TOOLS = [
    Tool("process_lineage", "lineage", {"type": "object", "properties": {"image": {"type": "string"}}, "required": ["image"]}, _lineage),
]


class TestAgentLoop(unittest.TestCase):
    def test_tool_call_then_verdict(self):
        calls = []

        def fake_post(url, payload, timeout):
            calls.append(payload)
            n = len(payload["messages"])
            if n == 2:  # initial (system + user) -> model requests a tool
                return {"choices": [{"message": {
                    "role": "assistant", "content": None,
                    "tool_calls": [{"id": "c1", "type": "function",
                                    "function": {"name": "process_lineage",
                                                 "arguments": '{"image": "evil.exe"}'}}],
                }}]}
            # after the tool result -> final JSON verdict
            self.assertEqual(payload["messages"][-1]["role"], "tool")
            return {"choices": [{"message": {"role": "assistant",
                "content": '{"verdict": "MALICIOUS", "confidence": 0.9, "reason": "lineage confirms"}'}}]}

        v = run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
                      TOOLS, "m", "http://x", post_fn=fake_post)
        self.assertEqual(v["verdict"], "MALICIOUS")
        self.assertEqual(v["confidence"], 0.9)
        self.assertEqual(len(calls), 2)

    def test_direct_verdict_without_tools(self):
        def fake_post(url, payload, timeout):
            return {"choices": [{"message": {"role": "assistant",
                "content": '{"verdict": "BENIGN", "confidence": 0.7, "reason": "normal"}'}}]}

        v = run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
                      TOOLS, "m", "http://x", post_fn=fake_post)
        self.assertEqual(v["verdict"], "BENIGN")

    def test_unknown_tool_is_handled(self):
        def fake_post(url, payload, timeout):
            if len(payload["messages"]) == 2:
                return {"choices": [{"message": {"role": "assistant", "content": None,
                    "tool_calls": [{"id": "c1", "type": "function",
                                    "function": {"name": "nope", "arguments": "{}"}}]}}]}
            return {"choices": [{"message": {"role": "assistant",
                "content": '{"verdict": "UNCERTAIN", "confidence": 0.5, "reason": ""}'}}]}

        v = run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
                      TOOLS, "m", "http://x", post_fn=fake_post)
        self.assertEqual(v["verdict"], "UNCERTAIN")


if __name__ == "__main__":
    unittest.main()

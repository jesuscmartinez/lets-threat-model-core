import unittest
from core.agents.agent_tools import AgentHelper


class TestAgentHelper(unittest.TestCase):
    def setUp(self):
        self.agent_helper = AgentHelper()

    def test_convert_uuids_to_ids(self):
        data_flow_report = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "nested": {
                "id": "123e4567-e89b-12d3-a456-426614174001",
                "items": [
                    {"id": "123e4567-e89b-12d3-a456-426614174002"},
                    {"id": "123e4567-e89b-12d3-a456-426614174003"},
                ],
            },
            "references": {
                "_id": "123e4567-e89b-12d3-a456-426614174004",
                "_ids": [
                    "123e4567-e89b-12d3-a456-426614174005",
                    "123e4567-e89b-12d3-a456-426614174006",
                ],
            },
        }

        expected_output = {
            "id": "uuid_1",
            "nested": {
                "id": "uuid_2",
                "items": [
                    {"id": "uuid_3"},
                    {"id": "uuid_4"},
                ],
            },
            "references": {
                "_id": "uuid_5",
                "_ids": [
                    "uuid_6",
                    "uuid_7",
                ],
            },
        }

        result = self.agent_helper.convert_uuids_to_ids(data_flow_report)
        self.assertEqual(result, expected_output)

    def test_convert_ids_to_uuids(self):
        data_flow_report = {
            "id": "uuid_1",
            "nested": {
                "id": "uuid_2",
                "items": [
                    {"id": "uuid_3"},
                    {"id": "uuid_4"},
                ],
            },
            "references": {
                "_id": "uuid_5",
                "_ids": [
                    "uuid_6",
                    "uuid_7",
                ],
            },
        }

        self.agent_helper.uuid_to_numbered_mapping = {
            "123e4567-e89b-12d3-a456-426614174000": "uuid_1",
            "123e4567-e89b-12d3-a456-426614174001": "uuid_2",
            "123e4567-e89b-12d3-a456-426614174002": "uuid_3",
            "123e4567-e89b-12d3-a456-426614174003": "uuid_4",
            "123e4567-e89b-12d3-a456-426614174004": "uuid_5",
            "123e4567-e89b-12d3-a456-426614174005": "uuid_6",
            "123e4567-e89b-12d3-a456-426614174006": "uuid_7",
        }

        expected_output = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "nested": {
                "id": "123e4567-e89b-12d3-a456-426614174001",
                "items": [
                    {"id": "123e4567-e89b-12d3-a456-426614174002"},
                    {"id": "123e4567-e89b-12d3-a456-426614174003"},
                ],
            },
            "references": {
                "_id": "123e4567-e89b-12d3-a456-426614174004",
                "_ids": [
                    "123e4567-e89b-12d3-a456-426614174005",
                    "123e4567-e89b-12d3-a456-426614174006",
                ],
            },
        }

        result = self.agent_helper.convert_ids_to_uuids(data_flow_report)
        self.assertEqual(result, expected_output)


if __name__ == "__main__":
    unittest.main()

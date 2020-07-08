"""
HEC Event Ingestor class
"""
from .base_event_ingestor import EventIngestor
import requests
from time import time, mktime
import concurrent.futures
import logging
import os
requests.urllib3.disable_warnings()

LOGGER = logging.getLogger("pytest-splunk-addon")

class HECEventIngestor(EventIngestor):
    """
    Class to ingest event via HEC
    """

    def __init__(self, required_configs):
        """
        init method for the class

        Args:
            required_configs(dict): {
                hec_uri: {splunk_hec_scheme}://{splunk_host}:{hec_port}/services/collector,
                session_headers(dict): {
                    "Authorization": f"Splunk <hec-token>",
                }
            }
        """
        self.hec_uri = required_configs.get("splunk_hec_uri")
        self.session_headers = required_configs.get("session_headers")

    def ingest(self, events):
        """
        Ingests event and metric data into splunk using HEC token via event endpoint.
        Args:
            data(dict): data dict with the info of the data to be ingested.

            format::
                {
                    "sourcetype": "sample_HEC",
                    "source": "sample_source",
                    "host": "sample_host",
                    "event": "event_str"
                }

            For batch ingestion of events in a single request at event endpoint provide a list of event dict to be ingested.
            format::
                [ 
                    {
                        "sourcetype": "sample_HEC",
                        "source": "sample_source",
                        "host": "sample_host",
                        "event": "event_str1"
                    },
                    {
                        "sourcetype": "sample_HEC",
                        "source": "sample_source",
                        "host": "sample_host",
                        "event": "event_str2"
                    },
                ]
        """
        data = list()
        for event in events:

            event_dict = {
                "sourcetype": event.metadata.get("sourcetype",
                                                 "pytest_splunk_addon"),
                "source": event.metadata.get("source",
                                             "pytest_splunk_addon:hec:event"),
                "event": event.event,
            }

            if event.metadata.get("host_type") in ("plugin", None):
                host = event.metadata.get("host")
            else:
                host = event.key_fields.get("host")
            if host:
                event_dict['host'] = host

            if event.metadata.get("timestamp_type").lower() == 'plugin':
                event_dict['time'] = event.time_values[0]
            elif event.metadata.get("timestamp_type").lower() == 'event':
                if event.time_values:
                    event_dict['time'] = event.time_values[0]
            data.append(event_dict)

        batch_event_list = []
        for i in range(0, len(data), 100):
            batch_event_list.append(data[i: i + 100])

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(self.__ingest, batch_event_list)

    def __ingest(self, data):
        try:
            response = requests.post(
                "{}/{}".format(self.hec_uri, "event"),
                auth=None,
                json=data,
                headers=self.session_headers,
                verify=False,
            )
            if response.status_code not in (200, 201):
                LOGGER.debug(
                    "Status code: {} \nReason: {} \ntext:{}".format(
                        response.status_code, response.reason, response.text
                    )
                )
                raise Exception

        except Exception as e:
            LOGGER.error(e)
            os._exit(0)

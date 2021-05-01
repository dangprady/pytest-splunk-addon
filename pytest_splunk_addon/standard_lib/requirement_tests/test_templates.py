import logging
import pytest
import time
import ast

INTERVAL = 3
RETRIES = 3


class ReqsTestTemplates(object):
    """
    Test templates to test the log files in the event_analytics folder
    """
    logger = logging.getLogger()

    # Function to remove the data model subset concatenated to fields from the dictionary
    # eg : All_traffic.dest -> dest else do nothing
    def process_str(self, in_str):
        new_dict = {}
        for k, v in in_str.items():
            # self.logger.info(k, v)
            b = k.split('.', 1)
            if len(b) == 1:
                new_dict.update({b[0]: v})
            else:
                new_dict.update({b[1]: v})
        return new_dict

    # Function to compare the fields extracted from XML and the fields extracted from Splunk search
    def compare(self, keyValueSPL, keyValueXML):
        keyValueprocessedSPL = self.process_str(keyValueSPL)
        flag = True
        for key, value in keyValueXML.items():
            res = key in keyValueprocessedSPL and value == keyValueprocessedSPL[key]
            if not res:
                self.logger.info(key + "="+ value + " pair in requirement file not in SPL extracted fields values")
                flag = False
        return flag

    def extract_tag(self, keyValueSPL):
        for key, value in keyValueSPL.items():
            if key == "tag":
                # Converting string to list
                self.logger.info(value)
                list_of_extracted_tags = value.strip('][').split(', ')
                c=[]
                for item in list_of_extracted_tags:
                    item= item.replace("'", "")
                    c.append(item)
                self.logger.info(list_of_extracted_tags)
                return c

    def get_associated_tags(selfself, datamodel):
        dict_datamodel_tag = {
            "Alerts": {
                "mandatory": "alert"
            },
            "Authentication":
            {
                "mandatory": "authentication",
                "Default_Authentication": "default",
                "Insecure_Authentication": ["cleartext", "insecure"],
                "Privileged_Authentication": ["privileged"]
            },
            # "Application_State": ["listening", "port", "process", "report", "service"],
            # "Certificates": ["certificate", "ssl", "tls"],
            # "Change": ["change", "audit", "endpoint", "network", "account", "instance"],
            # "Change_Analysis": ["change", "audit", "endpoint", "network", "account"],
            # "Databases": ["database", "instance", "stats", "session", "lock", "query", "tablespace", "stats"],
            # "DLP": ["dlp", "incident"],
            # "Email": ["email", "delivery", "content", "filter"],
            # "Endpoint": ["listening", "port", "process", "report", "service", "report", "endpoint", "filesystem", "registry"],
            # "Event_Signatures": ["track_event_signatures"],
            # "Interprocess_Messaging": ["messaging"],
            # "Intrusion_Detection": ["ids", "attack"],
            # "Inventory": ["inventory", "cpu", "memory", "network", "storage", "system", "version", "user", "virtual"],
            # "JVM": ["jvm", "threading", "runtime", "os", "compilation", "classloading", "memory"],
            # "Malware": ["malware", "attack", "malware", "operations"],
            "Network_Resolution":
            { "mandatory": ["network", "resolution", "dns"]
            }
            # "Network_Sessions": ["network", "session"],
            # "Network_Traffic": ["network", "communicate"],
            # "Performance": ["performance", "cpu", "facilities", "memory", "storage", "network", "os", "uptime", "time","synchronize"],
            # "Splunk_Audit": ["modaction", "invocation"],
            # "Ticket_Management": ["ticketing", "change", "incident", "problem"],
            # "Updates": ["update", "status", "error"],
            # "Vulnerabilities": ["report", "vulnerability"],
            # "Web": ["web", "proxy"]
        }
        for key in dict_datamodel_tag:
            if key == datamodel:
                return dict_datamodel_tag[key]
        return None

    def check_mandatory_tag(self, tags_search, associated_tags ):
        mandatory_associated = associated_tags["mandatory"]
        self.logger.info(type(mandatory_associated))
        self.logger.info(type(tags_search))
        self.logger.info(mandatory_associated)
        self.logger.info(tags_search)
        check = all(elem in tags_search  for elem in mandatory_associated)
        self.logger.info(check)
        return check

    @pytest.mark.splunk_searchtime_requirements
    def test_requirement_params(self, splunk_searchtime_requirement_param, splunk_search_util):
        model = splunk_searchtime_requirement_param["model"]
        dataset = splunk_searchtime_requirement_param["dataset"]
        escaped_event = splunk_searchtime_requirement_param["escaped_event"]
        filename = splunk_searchtime_requirement_param["filename"]
        sourcetype = splunk_searchtime_requirement_param["sourcetype"]
        key_values_xml = splunk_searchtime_requirement_param["Key_value_dict"]
        #self.logger.info(key_values_xml)
        result = False
        if model is None and escaped_event is None:
            self.logger.info("Issue parsing log file {}".format(filename))
            pytest.skip('Issue parsing log file')
        if model is None and escaped_event is not None:
            self.logger.info("No model present in file")
            pytest.skip('No model present in file')
        if sourcetype is None:
            self.logger.info("Issue finding sourcetype")
            assert result
        search = f" search source= pytest_splunk_addon:hec:raw sourcetype={sourcetype} {escaped_event} |fields * "

        # Search for getting both data model and field extractions
        #search = f"| datamodel {model} {dataset}  search | search source=	pytest_splunk_addon:hec:raw sourcetype={sourcetype} {escaped_event}"
        ingestion_check = splunk_search_util.checkQueryCountIsGreaterThanZero(
            search, interval=INTERVAL, retries=RETRIES
        )
        assert ingestion_check, (
            f"ingestion failure \nsearch={search}\n"
        )
        self.logger.info(f"ingestion_check: {ingestion_check}")

        keyValue_dict_SPL = splunk_search_util.getFieldValuesDict(
            search, interval=INTERVAL, retries=RETRIES
        )
        self.logger.info(type(keyValue_dict_SPL))
        extracted_tags = self.extract_tag(keyValue_dict_SPL)
        self.logger.info(extracted_tags)
        tags_based_on_datamodel = self.get_associated_tags(model)
        self.logger.info(tags_based_on_datamodel)

        mandatory_fullfilled = self.check_mandatory_tag(extracted_tags,tags_based_on_datamodel)
        self.logger.info(f"Mandatory Fulfilled : {mandatory_fullfilled}")
        self.logger.info(f"SPL dict: {keyValue_dict_SPL}")
        self.logger.info(f"key_values_xml:{key_values_xml}")

        field_extraction_check = self.compare(keyValue_dict_SPL, key_values_xml)
        self.logger.info(f"Field mapping check: {field_extraction_check}")

        assert field_extraction_check, (
            f"Issue with the field extraction.\nsearch={search}\n"
            f" Field_extraction_check: {field_extraction_check} \n"
        )

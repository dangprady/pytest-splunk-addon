"""
Generates test cases to verify the event analytics logs.
"""
import pytest
import logging
import os
import configparser
from xml.etree import cElementTree as ET
import re


LOGGER = logging.getLogger("pytest-splunk-addon")


class SrcRegex(object):
    def __init__(self):
        self.regex_src = None
        self.source_type = None


class keyValue(dict):
    def __init__(self):
        self = dict()

    def add(self, key, value):
        self[key] = value


class ReqsTestGenerator(object):
    """
    Generates test cases to test the events in the log files of the event anlytics folder
    * Provides the pytest parameters to the test_templates.py.
    Args:
        app_path (str): Path of the app package
    """
    logger = logging.getLogger()

    def __init__(self, app_path):
        logging.info("initializing ReqsTestGenerator class")
        self.package_path = app_path
        self.folder_path = os.path.join(str(self.package_path), "requirement_files")

    def generate_tests(self, fixture):
        """
        Generate the test cases based on the fixture provided
        Args:
            fixture(str): fixture name
        """
        if fixture.endswith("param"):
            yield from self.generate_cim_req_params()

    # Extract key values pair XML
    def extract_key_value_xml(self, event):
        key_value_dict = keyValue()
        for fields in event.iter('field'):
            if fields.get('name'):
                field_name = fields.get('name')
                field_value = fields.get('value')
                key_value_dict.add(field_name, field_value)
        # self.logger.info(key_value_dict)
        return key_value_dict

    def extract_transport_tag(self, event):
        for transport in event.iter('transport'):
            return transport.get('type')

    def strip_syslog_header(self, raw_event):
        # remove leading space chars
        raw_event = raw_event.strip()
        CEF_format_match = re.search(r"\s(CEF:\d\|[^\|]+\|([^\|]+)\|[^\|]+\|[^\|]+\|[^\|]+\|([^\|]+)\|(.*))", raw_event)
        if CEF_format_match:
            stripped_header = CEF_format_match.group(1)
            return stripped_header
        regex_rfc5424 = re.search(
            r"(?:(\d{4}[-]\d{2}[-]\d{2}[T]\d{2}[:]\d{2}[:]\d{2}(?:\.\d{1,6})?(?:[+-]\d{2}[:]\d{2}|Z)?)|-)\s(?:([\w][\w\d\.@-]*)|-)\s(.*)$",
            raw_event)
        if regex_rfc5424:
            stripped_header = regex_rfc5424.group(3)
            return stripped_header
        regex_rfc3164 = re.search(
            r"([A-Z][a-z][a-z]\s{1,2}\d{1,2}\s\d{2}[:]\d{2}[:]\d{2})\s+([\w][\w\d\.@-]*)\s(.*)$",
            raw_event)
        if regex_rfc3164:
            stripped_header = regex_rfc3164.group(3)
            return stripped_header
        if not (CEF_format_match and regex_rfc3164 and regex_rfc5424):
            return None

    def generate_cim_req_params(self):
        """
        Generate & Yield pytest.param for each test case.
        Params = Model_name with respective Event
        """
        req_file_path = self.folder_path
        req_test_id = 0
        if os.path.isdir(req_file_path):
            for file1 in os.listdir(req_file_path):
                filename = os.path.join(req_file_path, file1)
                LOGGER.info(filename)
                if filename.endswith(".log"):
                    try:
                        try:
                            self.check_xml_format(filename)
                        except Exception:
                            LOGGER.error("Invalid XML")
                        root = self.get_root(filename)
                        for event_tag in root.iter('event'):
                            unescaped_event = self.get_event(event_tag)
                            transport_type = self.extract_transport_tag(event_tag)
                            if transport_type == "syslog":
                                stripped_event = self.strip_syslog_header(unescaped_event)
                            else:
                                #todo: non syslog events are skipped currently until we support it
                                continue
                            if stripped_event is None:
                                LOGGER.error("Syslog event do not match CEF, RFC_3164, RFC_5424 format")
                                continue
                            escaped_event = self.escape_char_event(stripped_event)
                            model_list = self.get_models(event_tag)
                            # Fetching kay value pair from XML
                            key_value_dict = self.extract_key_value_xml(event_tag)
                            # self.logger.info(key_value_dict)
                            if len(model_list) == 0:
                                LOGGER.info("No model in this event")
                                continue
                            list_model_dataset_subdataset = []
                            for model in model_list:
                                model = model.replace(" ", "_")
                                # Function to extract data set
                                model_name = self.split_model(model)
                                list_model_dataset_subdataset.append(model_name)
                                logging.info(model_name)
                            req_test_id = req_test_id + 1
                            yield pytest.param(
                                {
                                    "model_list": list_model_dataset_subdataset,
                                    "escaped_event": escaped_event,
                                    "Key_value_dict": key_value_dict,
                                },
                                id=f"{model_list}::{filename}::req_test_id::{req_test_id}",
                            )
                    except Exception:
                        LOGGER.error("Issue with requirement file")

    def get_models(self, root):
        """
        Input: Root of the xml file
        Function to return list of models in each event of the log file
        """
        model_list = []
        for model in root.iter('model'):
            model_list.append(str(model.text))
        return model_list

    def split_model(self, model):
        """
        Input: Root of the xml file
        Function to return list of models in each event of the log file
        """
        model_name = model.split(':', 2)
        if len(model_name) == 3:
            model = model_name[0]
            dataset = model_name[1]
            subdataset = model_name[2]
            model = model.replace(" ", "_")
            model_dataset_subdaset = model + "_" + dataset + "_" +subdataset
        elif len(model_name) == 2:
            model = model_name[0]
            dataset = model_name[1]
            model = model.replace(" ", "_")
            model_dataset_subdaset = model + "_" + dataset
        else:
            model = model_name[0]
            model_dataset_subdaset = model

        return model_dataset_subdaset


    def get_event(self, root):
        """
        Input: Root of the xml file
        Function to return raw event string
        """
        event = None
        for raw in root.iter('raw'):
            event = raw.text
        return event

    def get_root(self, filename):
        """
        Input: Filename ending with .log extension
        Function to return raw event string
        """
        tree = ET.parse(filename)
        root = tree.getroot()
        return root

    def check_xml_format(self, file_name):
        if (ET.parse(file_name)):
            return True

    def escape_char_event(self, event):
        """
        Input: Event getting parsed
        Function to escape special characters in Splunk
        https://docs.splunk.com/Documentation/StyleGuide/current/StyleGuide/Specialcharacters
        """
        escape_splunk_chars = ["\\", "`", "~", "!", "@", "#", "$", "%",
                               "^", "&", "*", "(", ")", "-", "=", "+", "[", "]", "}", "{", "|",
                               ";", ":", "'", "\,", "<", ">", "\/", "?", "IN", "AS", "BY", "OVER", "WHERE", "LIKE"]
        for character in escape_splunk_chars:
            event = event.replace(character, '\\' + character)
        return event

    #Not used as sending data using SC4S
    def extractRegexTransforms(self):
        """
        Requirement : app transform.conf
        Return: SrcRegex objects list containing pair of regex and sourcetype
        """
        parser = configparser.ConfigParser(interpolation=None)
        transforms_path = os.path.join(str(self.package_path), "default/transforms.conf")
        parser.read_file(open(transforms_path))
        list_src_regex = []
        for stanza in parser.sections():
            stanza_keys = list(parser[stanza].keys())
            obj = SrcRegex()
            if "dest_key" in stanza_keys:
                if str(parser[stanza]["dest_key"]) == "MetaData:Sourcetype":
                    for key in stanza_keys:
                        key_value = str(parser[stanza][key])
                        if key == "regex":
                            obj.regex_src = key_value
                        if key == "format":
                            obj.source_type = key_value
                    list_src_regex.append(obj)
        return list_src_regex

    def extractSourcetype(self, list_src_regex, event):
        """
        Input: event, List of SrcRegex
        Return:Sourcetype of the event
        """
        sourcetype = None
        for regex_src_obj in list_src_regex:
            regex_match = re.search(regex_src_obj.regex_src, event)
            if regex_match:
                _, sourcetype = str(regex_src_obj.source_type).split('::', 1)
        return sourcetype
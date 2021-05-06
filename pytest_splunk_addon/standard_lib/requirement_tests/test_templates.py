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
    dict_datamodel_tag = {
            'Alerts': ['alert'],
            'Authentication': ['authentication'],
            'Authentication_Default_Authentication': ['default', 'authentication'],
            'Authentication_Insecure_Authentication': ['authentication', 'insecure'],
            'Authentication_Insecure_Authentication.2': ['authentication', 'cleartext'],
            'Authentication_PrivilegedAuthentication': ['authentication', 'privileged'],
            'Certificates': ['certificate'],
            'Certificates_SSL': ['certificate', 'ssl'],
            'Change': ['change'],
            'Change_Auditing_Changes': ['change', 'audit'],
            'Change_Endpoint_Changes': ['change', 'endpoint'],
            'Change_Network_Changes': ['change', 'network'],
            'Change_Account_Management': ['change', 'account'],
            'Change_Instance_Changes': ['change', 'instance'],
            'Compute_Inventory_CPU': ['inventory', 'cpu'],
            'Compute_Inventory_Memory': ['inventory', 'memory'],
            'Compute_Inventory_Network': ['inventory', 'network'],
            'Compute_Inventory_Storage': ['inventory', 'storage'],
            'Compute_Inventory_OS': ['inventory', 'system', 'version'],
            'Compute_Inventory_User': ['inventory', 'user'],
            'Compute_Inventory_User_Default_Accounts': ['inventory', 'user', 'default'],
            'Compute_Inventory_Virtual_OS': ['inventory', 'virtual'],
            'Compute_Inventory_Virtual_OS_Snapshot': ['inventory', 'virtual', 'snapshot'],
            'Compute_Inventory_Virtual_OS_Tools': ['inventory', 'virtual', 'tools'], 'Databases': ['database'],
            'Databases_Database_Instance': ['database', 'instance'],
            'Databases_Database_Instance_Instance_Stats': ['database', 'instance', 'stats'],
            'Databases_Database_Instance_Session_Info': ['database', 'instance', 'session'],
            'Databases_Database_Instance_Lock_Info': ['database', 'instance', 'lock'],
            'Databases_Database_Query': ['database', 'query'],
            'Databases_Database_Query_tablespace': ['database', 'query', 'tablespace'],
            'Databases_Database_Query_Query_Stats': ['database', 'query', 'stats'], 'DLP': ['dlp', 'incident'],
            'Email': ['email'],
            'Email_Delivery': ['email', 'delivery'],
            'Email_Content': ['email', 'content'],
            'Email_Filtering': ['email', 'filter'],
            'Endpoint_ports': ['listening', 'port'],
            'Endpoint_Processes': ['process', 'report'],
            'Endpoint_Filesystem': ['endpoint', 'filesystem'],
            'Endpoint_Services': ['service', 'report'],
            'Endpoint_Registry': ['endpoint', 'registry'],
            'Event_Signatures_Signatures': ['track_event_signatures'],
            'Interprocess_Messaging': ['messaging'],
            'Intrusion_Detection': ['ids', 'attack'],
            'JVM': ['jvm'], 'JVM_Runtime': ['jvm', 'runtime'],
            'JVM_OS': ['jvm', 'os'],
            'JVM_Classloading': ['jvm', 'classloading'],
            'JVM_Memory': ['jvm', 'memory'],
            'JVM_Threading': ['jvm', 'threading'],
            'JVM_Compilation': ['jvm', 'compilation'],
            'Malware_Malware_Attacks': ['malware', 'attack'],
            'Malware_Malware_Operations': ['malware', 'operations'],
            'Network_Resolution': ['network', 'resolution', 'dns'],
            'Network_Sessions': ['network', 'session'],
            'Network_Sessions_Session_Start': ['network', 'session', 'start'],
            'Network_Sessions_Session_End': ['network', 'session', 'end'],
            'Network_Sessions_DHCP': ['network', 'session', 'dhcp'],
            'Network_Sessions_VPN': ['network', 'session', 'vpn'],
            'Network_Traffic': ['network', 'communicate'],
            'Performance_CPU': ['performance', 'cpu'],
            'Performance_Facilities': ['performance', 'facilities'],
            'Performance_Memory': ['performance', 'memory'],
            'Performance_Storage': ['performance', 'storage'],
            'Performance_OS': ['performance', 'os'],
            'Performance_OS_Timesync': ['performance', 'os', 'time', 'synchronize'],
            'Performance_OS_Uptime': ['performance', 'os', 'uptime'],
            'Splunk_Audit': ['modaction'],
            'Splunk_Audit_Modular_Action_Invocations': ['modaction', 'invocation'],
            'Ticket_Management': ['ticketing'],
            'Ticket_Management_Change': ['ticketing', 'change'],
            'Ticket_Management_Incident': ['ticketing', 'incident'],
            'Ticket_Management_Problem': ['ticketing', 'problem'],
            'Updates': ['update', 'status'],
            'Updates_Update_Errors': ['update', 'error'],
            'Vulnerabilities': ['report', 'vulnerability'],
            'Web': ['web'],
            'Web_proxy': ['web', 'proxy']
        }


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
                    item = item.replace("'", "")
                    c.append(item)
                self.logger.info(list_of_extracted_tags)
                return c

    def fetch_datamodel_by_tags(self,tag):
        list_matching_datamodel = []
        for datamodel, tags in self.dict_datamodel_tag.items():
            if set(tags) <= set(tag):
                list_matching_datamodel.append(datamodel)
        return list_matching_datamodel

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
        self.logger.info(keyValue_dict_SPL)
        extracted_tags = self.extract_tag(keyValue_dict_SPL)
        self.logger.info(extracted_tags)
        datamodel_based_on_tag = self.fetch_datamodel_by_tags(extracted_tags)
        self.logger.info(datamodel_based_on_tag)

        # mandatory_fullfilled = self.check_mandatory_tag(extracted_tags,tags_based_on_datamodel)
        # self.logger.info(f"Mandatory Fulfilled : {mandatory_fullfilled}")
        self.logger.info(f"SPL dict: {keyValue_dict_SPL}")
        self.logger.info(f"key_values_xml:{key_values_xml}")

        field_extraction_check = self.compare(keyValue_dict_SPL, key_values_xml)
        self.logger.info(f"Field mapping check: {field_extraction_check}")

        assert field_extraction_check, (
            f"Issue with the field extraction.\nsearch={search}\n"
            f" Field_extraction_check: {field_extraction_check} \n"
        )

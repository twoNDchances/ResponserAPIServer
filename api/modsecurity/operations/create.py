from flask import request
from flask_restful import Resource
from ansible_runner import run
from json import loads, dumps
import uuid
import shutil
from ...storage import response_elasticsearch, ES_MAX_RESULT, ANSIBLE_FIREWALL_USERNAME, ANSIBLE_FIREWALL_PASSWORD, ANSIBLE_DATA_DIR, ANSIBLE_INVENTORY


class ModSecurityCreation(Resource):
    def post(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        try:
            loads(request.data)
        except:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        responser_name = request_body.get('responserName')
        responser_configuration = request_body.get('responserConfiguration')
        if not all([responser_name, responser_configuration]):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields ["responser_name", "responser_configuration"]'
            }, 400
        if not isinstance(responser_name, str) or not isinstance(responser_configuration, dict):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["responser_name" => (string), "responser_configuration" => (json)]'
            }, 406
        modsecurity = response_elasticsearch.search(index='responser-modsecurity', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if modsecurity['hits']['hits'].__len__() > 0:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: Responser Name is exist'
            }, 406
        is_enabled_configuration = responser_configuration.get('is_enabled')
        ip_address = responser_configuration.get('ip_address')
        payload = responser_configuration.get('payload')
        advanced = responser_configuration.get('advanced')
        if is_enabled_configuration is None or not all([ip_address, payload, advanced]):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "responser_configuration" ["is_enabled", "ip_address", "payload", "advanced"]'
            }, 400
        if not isinstance(is_enabled_configuration, bool) or not isinstance(ip_address, dict) or not isinstance(payload, dict) or not isinstance(advanced, dict):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["is_enabled" => (boolean), "ip_address" => (json), "payload" => (json), "advanced" => (json)]'
            }, 406
        ip_address_is_used = ip_address.get('is_used')
        ip_source_field = ip_address.get('ip_source_field')
        paranoia_level = ip_address.get('paranoia_level')
        anomaly_score = ip_address.get('anomaly_score')
        if ip_address_is_used is None or not all([ip_source_field, paranoia_level, anomaly_score]):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "ip_address" ["is_used", "ip_source_field", "paranoia_level", "anomaly_socre"]'
            }, 400
        if not isinstance(ip_address_is_used, bool) or not isinstance(ip_source_field, str) or not isinstance(paranoia_level, int) or not isinstance(anomaly_score, int):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["is_used" => (boolean), "ip_source_field" => (string), "paranoia_level" => (integer), "anomaly_score" => (integer)]'
            }, 406
        if paranoia_level not in range(1, 5) or anomaly_score <= 0:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: "paranoia_level" must in [1, 2, 3, 4] and "anomaly_score" must greater than 0'
            }, 406
        payload_is_used = payload.get('is_used')
        regex_field = payload.get('regex_field')
        root_cause_field = payload.get('root_cause_field')
        if payload_is_used is None or not all([regex_field, root_cause_field]):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "payload" ["is_used", "regex_field", "root_cause_field"]'
            }, 400
        if not isinstance(payload_is_used, bool) or not isinstance(regex_field, str) or not isinstance(root_cause_field, str):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["is_used" => (boolean), "regex_field" => (string), "root_cause_field" => (string)]'
            }, 406
        advanced_is_enabled = advanced.get('is_enabled')
        threshold = advanced.get('threshold')
        time_window_seconds = advanced.get('time_window_seconds')
        if advanced_is_enabled is None or not all([threshold, time_window_seconds]):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "advanced" ["is_enabled", "threshold", "time_window_seconds"]'
            }, 400
        if not isinstance(advanced_is_enabled, bool) or not isinstance(threshold, int) or not isinstance(time_window_seconds, int):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["is_enabled" => (boolean), "threshold" => (integer), "time_window_seconds" => (integer)]'
            }, 406
        if threshold <= 1 or time_window_seconds <= 0:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: "threshold" must be greater than 1 and "time_window_seconds" must be greater than 0'
            }, 406
        if ip_address_is_used is False and payload_is_used is False:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: "ip_address" or "payload" must be enabled'
            }, 406
        unique_id = uuid.uuid4()
        runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            module='ping',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id
        )
        if runner.rc != 0:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'InternalServerError: Perform test connection with Firewall Node fail'
            }, 500
        for event in runner.events:
            if event['event'] == 'runner_on_ok':
                if event['event_data']['res']['ping'] != 'pong':
                    return {
                        'type': 'modsecurity',
                        'data': None,
                        'reason': 'InternalServerError: Test ping to Firewall Node fail'
                    }, 500
        response_elasticsearch.index(index='responser-modsecurity', document={
            'responser_name': responser_name,
            'responser_configuration': dumps(responser_configuration)
        })
        shutil.rmtree(path=f'{ANSIBLE_DATA_DIR.replace(".", "")}artifacts/{unique_id}', ignore_errors=True)
        return {
            'type': 'modsecurity',
            'data': None,
            'reason': 'Success'
        }

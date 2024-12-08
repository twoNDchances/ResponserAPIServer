from flask import request
from flask_restful import Resource
from ansible_runner import run
from json import loads, dumps
from requests import get
import shutil
import uuid
from ...storage import (
    response_elasticsearch, 
    ES_MAX_RESULT, 
    ANSIBLE_FIREWALL_USERNAME, 
    ANSIBLE_FIREWALL_PASSWORD, 
    ANSIBLE_DATA_DIR, 
    ANSIBLE_INVENTORY,
    ANSIBLE_MODSEC_CONAME,
    RABBITMQ_HOST,
    RABBITMQ_MANAGEMENT_PORT,
    RABBITMQ_USERNAME,
    RABBITMQ_PASSWORD
)


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
        based_payload = payload.get('based_payload')
        regex_field = payload.get('regex_field')
        root_cause_field = payload.get('root_cause_field')
        if payload_is_used is None or based_payload is None or not all([regex_field, root_cause_field]):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "payload" ["is_used", "based_payload", "regex_field", "root_cause_field"]'
            }, 400
        if not isinstance(payload_is_used, bool) or not isinstance(based_payload, bool) or not isinstance(regex_field, str) or not isinstance(root_cause_field, str):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["is_used" => (boolean), "based_payload" => (boolean), "regex_field" => (string), "root_cause_field" => (string)]'
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
        try:
            rabbitmq_response = get(
                url=f'http://{RABBITMQ_HOST}:{RABBITMQ_MANAGEMENT_PORT}/api/healthchecks/node', 
                auth=(
                    RABBITMQ_USERNAME, 
                    RABBITMQ_PASSWORD
                )
            )
            if rabbitmq_response.status_code != 200:
                return {
                    'type': 'modsecurity',
                    'data': None,
                    'reason': f'InternalServerError: RabbitMQ healthcheck fail with HTTP status code {rabbitmq_response.status_code}'
                }, 500
        except:
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': f'InternalServerError: Can\'t perform GET request to RabbitMQ for connection testing'
            }, 500
        unique_id = uuid.uuid4()
        runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/modsecurity/playbooks/ansible_check_modsecurity.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'modsec_container_name': ANSIBLE_MODSEC_CONAME
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id
        )
        error_message = None
        for event in runner.events:
            if event.get('event') == 'runner_on_unreachable':
                error_message = event['stdout']
                break
            if event.get('event') == 'runner_on_failed':
                error_message = event['stdout']
                break
        if runner.status == 'failed':
            shutil.rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id}', ignore_errors=True)
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'InternalServerError' if error_message is None else f'InternalServerError: {error_message}'
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

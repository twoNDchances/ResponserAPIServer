from flask import request
from flask_restful import Resource
from ansible_runner import run
from json import loads
from prometheus_api_client import PrometheusConnect
from re import sub
from requests import get
from shutil import rmtree
from uuid import uuid4
from yaml import safe_load
from ...storage import (
    response_elasticsearch,
    ES_USER,
    ES_PASS,
    ES_MAX_RESULT,
    ANSIBLE_DATA_DIR,
    ANSIBLE_INVENTORY,
    ANSIBLE_FIREWALL_USERNAME,
    ANSIBLE_FIREWALL_PASSWORD,
    ANSIBLE_SWARM_USERNAME,
    ANSIBLE_SWARM_PASSWORD,
    ANSIBLE_MODSEC_CONAME,
    RABBITMQ_HOST,
    RABBITMQ_MANAGEMENT_PORT,
    RABBITMQ_USERNAME,
    RABBITMQ_PASSWORD,
    PROMETHEUS_HOST,
    PROMETHEUS_PORT
)


class ResourceCreations(Resource):
    def post(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'resources',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        try:
            loads(request.data)
        except:
            return {
                'type': 'resources',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        elasticsearch_username = request_body.get('loadResourceElasticsearchUsername')
        elasticsearch_password = request_body.get('loadResourceElasticsearchPassword')
        resource_definition = request_body.get('resourceDefinition')
        if elasticsearch_username is None or elasticsearch_password is None or resource_definition is None:
            return {
                'type': 'resources',
                'data': None,
                'reason': 'BadRequest: "loadResourceElasticsearchUsername", "loadResourceElasticsearchPassword", "resourceDefinition" are required'
            }, 400
        if elasticsearch_username != ES_USER or elasticsearch_password != ES_PASS:
            return {
                'type': 'storages', 
                'reason': 'Unauthorized: Incorrect Username or Password', 
                'data': None
            }, 401
        try:
            yaml_configuration = dict(safe_load(request_body.get('resourceDefinition')))
        except:
            return {
                'type': 'resources',
                'data': None,
                'reason': 'BadRequest: Resource Definition must be YAML'
            }, 400
        iptables = yaml_configuration.get('iptables')
        modsecurity = yaml_configuration.get('modsecurity')
        swarm = yaml_configuration.get('swarm')
        logs: dict[dict[str, None | dict | str]] = {
            'iptables': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'responser_name': [],
                    'responser_configuration': []
                },
                'others': [],
                'passed': []
            },
            'modsecurity': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'responser_name': [],
                    'responser_configuration': []
                },
                'others': [],
                'passed': []
            },
            'swarm': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'responser_name': [],
                    'responser_configuration': [],
                    'current_nums': []
                },
                'others': [],
                'passed': []
            }
        }
        if iptables is not None:
            if not isinstance(iptables, list):
                logs['iptables']['datatype'] = 'Wrong, must be (list)'
            else:
                is_error = False
                iptables_passed_list = []
                for iptable in iptables:
                    responser_name = iptable.get('responser_name')
                    responser_configuration = self.normalize_string(text=iptable.get('responser_configuration'))
                    if not all([responser_name, responser_configuration]):
                        logs['iptables']['fields'].append(f'Missing ["responser_name", "responser_configuration"]')
                        continue
                    if not isinstance(responser_name, str):
                        logs['iptables']['validations']['responser_name'].append('"responser_name" must be a (string)')
                        continue
                    if not isinstance(responser_configuration, str):
                        logs['iptables']['validations']['responser_configuration'].append('"responser_configuration" must be a (string)')
                        continue
                    if sum(1 for d in iptables if responser_name in d.values()) > 1:
                        logs['iptables']['validations']['responser_name'].append(f'{responser_name} is exist in your YAML file')
                        continue
                    elasticsearch_iptables = response_elasticsearch.search(index='responser-iptables', query={
                        'term': {
                            'responser_name.keyword': responser_name
                        }
                    }, size=ES_MAX_RESULT).raw['hits']['hits']
                    if elasticsearch_iptables.__len__() > 0:
                        logs['iptables']['validations']['responser_name'].append(f'{responser_name} is exist in Elasticsearch')
                        continue
                    try:
                        responser_configuration: dict = loads(responser_configuration)
                    except:
                        logs['iptables']['validations']['responser_configuration'].append(f'"responser_configuration" of {responser_name} must be JSON format')
                        continue
                    is_enabled_configuration = responser_configuration.get('is_enabled')
                    target_ip_field = responser_configuration.get('target_ip_field')
                    is_ruthless = responser_configuration.get('is_ruthless')
                    limit_duration_minutes = responser_configuration.get('limit_duration_minutes')
                    block_duration_minutes = responser_configuration.get('block_duration_minutes')
                    rate_limitation = responser_configuration.get('rate_limitation')
                    advanced = responser_configuration.get('advanced')
                    if is_enabled_configuration is None or is_ruthless is None or limit_duration_minutes is None or block_duration_minutes is None:
                        logs['iptables']['fields'].append('Missing requirement fields from "responser_configuration" ["is_enabled", "is_ruthless", "target_ip_field", "limit_duration_minutes", "block_duration_minutes", "rate_limitation", "advanced"]')
                        continue
                    if not all([target_ip_field, rate_limitation, advanced]):
                        logs['iptables']['fields'].append('Missing requirement fields from "responser_configuration" ["is_enabled", "is_ruthless", "target_ip_field", "limit_duration_minutes", "block_duration_minutes", "rate_limitation", "advanced"]')
                        continue
                    if not isinstance(is_enabled_configuration, bool) or not isinstance(is_ruthless, bool) or not isinstance(target_ip_field, str) or not isinstance(limit_duration_minutes, int) or not isinstance(block_duration_minutes, int) or not isinstance(rate_limitation, dict) or not isinstance(advanced, dict):
                        logs['iptables']['validations']['responser_configuration'].append('Invalid datatype ["is_enabled" => (boolean), "is_ruthless" => (boolean), "target_ip_field" => (string), "limit_duration_minutes" => (integer), "block_duration_minutes" => (integer), "rate_limitation" => (json), "advanced" => (json)]')
                        continue
                    if not (limit_duration_minutes > 0) or not (block_duration_minutes > 0):
                        logs['iptables']['validations']['responser_configuration'].append('"limit_duration_minutes", "block_duration_minutes" must be greater than 0')
                        continue
                    packet_nums = rate_limitation.get('packet_nums')
                    duration_type = rate_limitation.get('duration_type')
                    burst = rate_limitation.get('burst')
                    if packet_nums is None or burst is None:
                        logs['iptables']['validations']['responser_configuration'].append('Missing requirement fields from "rate_limitation" ["packet_nums", "duration_type", "burst"]')
                        continue
                    if not duration_type:
                        logs['iptables']['validations']['responser_configuration'].append('Missing requirement fields from "rate_limitation" ["packet_nums", "duration_type", "burst"]')
                        continue
                    if not isinstance(packet_nums, int) or not isinstance(duration_type, str) or not isinstance(burst, int):
                        logs['iptables']['validations']['responser_configuration'].append('Invalid datatype ["packet_nums" => (integer), "duration_type" => (string), "burst" => (integer)]')
                        continue
                    if not (packet_nums > 0) or not (burst > 0):
                        logs['iptables']['validations']['responser_configuration'].append('"packet_nums", "burst" must be greater than 0')
                        continue
                    if duration_type not in ['s', 'm', 'h', 'd']:
                        logs['iptables']['validations']['responser_configuration'].append('"duration_type" must be in ["s" => (second), "m" => (minute), "h" => (hour), "d" => (day)]')
                        continue
                    is_enabled = advanced.get('is_enabled')
                    threshold = advanced.get('threshold')
                    time_window_seconds = advanced.get('time_window_seconds')
                    if is_enabled is None:
                        logs['iptables']['validations']['responser_configuration'].append('Missing requirement fields from "advanced" ["is_enabled", "threshold", "time_window_seconds"]')
                        continue
                    if not all([threshold, time_window_seconds]):
                        logs['iptables']['validations']['responser_configuration'].append('Missing requirement fields from "advanced" ["is_enabled", "threshold", "time_window_seconds"]')
                        continue
                    if not isinstance(is_enabled, bool) or not isinstance(threshold, int) or not isinstance(time_window_seconds, int):
                        logs['iptables']['validations']['responser_configuration'].append('Invalid datatype ["is_enabled" => (boolean), "threshold" => (integer), "time_window_seconds" => (integer)]')
                        continue
                    iptables_passed_list.append(iptable)
                if iptables_passed_list.__len__() > 0:
                    unique_id = uuid4()
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
                    error_message = None
                    for event in runner.events:
                        if event.get('event') == 'runner_on_unreachable':
                            error_message = event['stdout']
                            break
                        if event.get('event') == 'runner_on_failed':
                            error_message = event['stdout']
                            break
                    if runner.status == 'failed':
                        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id}', ignore_errors=True)
                        logs['iptables']['others'].append(error_message)
                        is_error = True
                    if is_error is False:
                        for iptables_passed in iptables_passed_list:
                            responser_name = iptables_passed.get('responser_name')
                            responser_configuration = self.normalize_string(text=iptables_passed.get('responser_configuration'))
                            response_elasticsearch.index(index='responser-iptables', document={
                                'responser_name': responser_name,
                                'responser_configuration': responser_configuration
                            }, refresh='wait_for')
                            logs['iptables']['passed'].append(f'{responser_name}')
        if modsecurity is not None:
            if not isinstance(modsecurity, list):
                logs['modsecurity']['datatype'] = 'Wrong, must be (list)'
            else:
                is_error = False
                modsecurity_passed_list = []
                for modsec in modsecurity:
                    responser_name = modsec.get('responser_name')
                    responser_configuration = self.normalize_string(text=modsec.get('responser_configuration'))
                    if not all([responser_name, responser_configuration]):
                        logs['modsecurity']['fields'].append(f'Missing ["responser_name", "responser_configuration"]')
                        continue
                    if not isinstance(responser_name, str):
                        logs['modsecurity']['validations']['responser_name'].append('"responser_name" must be a (string)')
                        continue
                    if not isinstance(responser_configuration, str):
                        logs['modsecurity']['validations']['responser_configuration'].append('"responser_configuration" must be a (string)')
                        continue
                    if sum(1 for d in modsecurity if responser_name in d.values()) > 1:
                        logs['modsecurity']['validations']['responser_name'].append(f'{responser_name} is exist in your YAML file')
                        continue
                    elasticsearch_modsecurity = response_elasticsearch.search(index='responser-modsecurity', query={
                        'term': {
                            'responser_name.keyword': responser_name
                        }
                    }, size=ES_MAX_RESULT).raw['hits']['hits']
                    if elasticsearch_modsecurity.__len__() > 0:
                        logs['modsecurity']['validations']['responser_name'].append(f'{responser_name} is exist in Elasticsearch')
                        continue
                    try:
                        responser_configuration: dict = loads(responser_configuration)
                    except:
                        logs['modsecurity']['validations']['responser_configuration'].append(f'"responser_configuration" of {responser_name} must be JSON format')
                        continue
                    is_enabled_configuration = responser_configuration.get('is_enabled')
                    ip_address = responser_configuration.get('ip_address')
                    payload = responser_configuration.get('payload')
                    advanced = responser_configuration.get('advanced')
                    if is_enabled_configuration is None or not all([ip_address, payload, advanced]):
                        logs['modsecurity']['validations']['responser_configuration'].append('Missing requirement fields from "responser_configuration" ["is_enabled", "ip_address", "payload", "advanced"]')
                        continue
                    if not isinstance(is_enabled_configuration, bool) or not isinstance(ip_address, dict) or not isinstance(payload, dict) or not isinstance(advanced, dict):
                        logs['modsecurity']['validations']['responser_configuration'].append('Invalid datatype ["is_enabled" => (boolean), "ip_address" => (json), "payload" => (json), "advanced" => (json)]')
                        continue
                    ip_address_is_used = ip_address.get('is_used')
                    ip_source_field = ip_address.get('ip_source_field')
                    paranoia_level = ip_address.get('paranoia_level')
                    anomaly_score = ip_address.get('anomaly_score')
                    if ip_address_is_used is None or not all([ip_source_field, paranoia_level, anomaly_score]):
                        logs['modsecurity']['validations']['responser_configuration'].append('Missing requirement fields from "ip_address" ["is_used", "ip_source_field", "paranoia_level", "anomaly_socre"]')
                        continue
                    if not isinstance(ip_address_is_used, bool) or not isinstance(ip_source_field, str) or not isinstance(paranoia_level, int) or not isinstance(anomaly_score, int):
                        logs['modsecurity']['validations']['responser_configuration'].append('Invalid datatype ["is_used" => (boolean), "ip_source_field" => (string), "paranoia_level" => (integer), "anomaly_score" => (integer)]')
                        continue
                    if paranoia_level not in range(1, 5) or anomaly_score <= 0:
                        logs['modsecurity']['validations']['responser_configuration'].append('"paranoia_level" must in [1, 2, 3, 4] and "anomaly_score" must greater than 0')
                        continue
                    payload_is_used = payload.get('is_used')
                    based_payload = payload.get('based_payload')
                    regex_field = payload.get('regex_field')
                    root_cause_field = payload.get('root_cause_field')
                    if payload_is_used is None or based_payload is None or not all([regex_field, root_cause_field]):
                        logs['modsecurity']['validations']['responser_configuration'].append('Missing requirement fields from "payload" ["is_used", "based_payload", "regex_field", "root_cause_field"]')
                        continue
                    if not isinstance(payload_is_used, bool) or not isinstance(based_payload, bool) or not isinstance(regex_field, str) or not isinstance(root_cause_field, str):
                        logs['modsecurity']['validations']['responser_configuration'].append('Invalid datatype ["is_used" => (boolean), "based_payload" => (boolean), "regex_field" => (string), "root_cause_field" => (string)]')
                        continue
                    advanced_is_enabled = advanced.get('is_enabled')
                    threshold = advanced.get('threshold')
                    time_window_seconds = advanced.get('time_window_seconds')
                    if advanced_is_enabled is None or not all([threshold, time_window_seconds]):
                        logs['modsecurity']['validations']['responser_configuration'].append('Missing requirement fields from "advanced" ["is_enabled", "threshold", "time_window_seconds"]')
                        continue
                    if not isinstance(advanced_is_enabled, bool) or not isinstance(threshold, int) or not isinstance(time_window_seconds, int):
                        logs['modsecurity']['validations']['responser_configuration'].append('Invalid datatype ["is_enabled" => (boolean), "threshold" => (integer), "time_window_seconds" => (integer)]')
                        continue
                    if threshold <= 1 or time_window_seconds <= 0:
                        logs['modsecurity']['validations']['responser_configuration'].append('"threshold" must be greater than 1 and "time_window_seconds" must be greater than 0')
                        continue
                    if ip_address_is_used is False and payload_is_used is False:
                        logs['modsecurity']['validations']['responser_configuration'].append('"ip_address" or "payload" must be enabled')
                        continue
                    modsecurity_passed_list.append(modsec)
                if modsecurity_passed_list.__len__() > 0:
                    try:
                        rabbitmq_response = get(
                            url=f'http://{RABBITMQ_HOST}:{RABBITMQ_MANAGEMENT_PORT}/api/healthchecks/node', 
                            auth=(
                                RABBITMQ_USERNAME, 
                                RABBITMQ_PASSWORD
                            )
                        )
                        if rabbitmq_response.status_code != 200:
                            logs['modsecurity']['others'].append(f'RabbitMQ healthcheck fail with HTTP status code {rabbitmq_response.status_code}')
                            is_error = True
                    except:
                        logs['modsecurity']['others'].append('Can\'t perform GET request to RabbitMQ for connection testing')
                        is_error = True
                    if is_error is False:
                        unique_id = uuid4()
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
                            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id}', ignore_errors=True)
                            logs['modsecurity']['others'].append(error_message)
                            is_error = True
                    if is_error is False:
                        for modsecurity_passed in modsecurity_passed_list:
                            responser_name = modsecurity_passed.get('responser_name')
                            responser_configuration = self.normalize_string(text=modsecurity_passed.get('responser_configuration'))
                            response_elasticsearch.index(index='responser-modsecurity', document={
                                'responser_name': responser_name,
                                'responser_configuration': responser_configuration
                            }, refresh='wait_for')
                            logs['modsecurity']['passed'].append(f'{responser_name}')
        if swarm is not None:
            if not isinstance(swarm, list):
                logs['swarm']['datatype'] = 'Wrong, must be (list)'
            else:
                is_error = False
                swarm_passed_list = []
                for swm in swarm:
                    responser_name = swm.get('responser_name')
                    responser_configuration = self.normalize_string(text=swm.get('responser_configuration'))
                    current_nums = swm.get('current_nums')
                    if not all([responser_name, responser_configuration, current_nums]):
                        logs['swarm']['fields'].append(f'Missing ["responser_name", "responser_configuration"]')
                        continue
                    if not isinstance(responser_name, str):
                        logs['swarm']['validations']['responser_name'].append('"responser_name" must be a (string)')
                        continue
                    if not isinstance(responser_configuration, str):
                        logs['swarm']['validations']['responser_configuration'].append('"responser_configuration" must be a (string)')
                        continue
                    if not isinstance(current_nums, int):
                        logs['swarm']['validations']['current_nums'].append('"current_nums" must be a (integer)')
                        continue
                    if sum(1 for d in swarm if responser_name in d.values()) > 1:
                        logs['swarm']['validations']['responser_name'].append(f'{responser_name} is exist in your YAML file')
                        continue
                    elasticsearch_swarm = response_elasticsearch.search(index='responser-swarm', query={
                        'term': {
                            'responser_name.keyword': responser_name
                        }
                    }, size=ES_MAX_RESULT).raw['hits']['hits']
                    if elasticsearch_swarm.__len__() > 0:
                        logs['swarm']['validations']['responser_name'].append(f'{responser_name} is exist in Elasticsearch')
                        continue
                    try:
                        responser_configuration: dict = loads(responser_configuration)
                    except:
                        logs['swarm']['validations']['responser_configuration'].append(f'"responser_configuration" of {responser_name} must be JSON format')
                        continue
                    is_enabled = responser_configuration.get('is_enabled')
                    scaling = responser_configuration.get('scaling')
                    if is_enabled is None or not all([scaling]):
                        logs['swarm']['validations']['responser_configuration'].append('Missing requirement fields from "responser_configuration" ["is_enabled", "scaling"]')
                        continue
                    if not isinstance(is_enabled, bool) or not isinstance(scaling, dict):
                        logs['swarm']['validations']['responser_configuration'].append('Invalid datatype ["is_enabled" => (boolean), "scaling" => (json)')
                        continue
                    up_nums = scaling.get('up_nums')
                    down_nums = scaling.get('down_nums')
                    if not all([up_nums, down_nums, current_nums]):
                        logs['swarm']['validations']['responser_configuration'].append('Missing requirement fields from "scaling" ["up_nums", "down_nums"]')
                        continue
                    if not isinstance(up_nums, int) or not isinstance(down_nums, int):
                        logs['swarm']['validations']['responser_configuration'].append('Invalid datatype ["up_nums" => (integer), "down_nums" => (integer)]')
                        continue
                    if not isinstance(current_nums, int):
                        logs['swarm']['validations']['current_nums'].append('Invalid datatype ["current_nums" => (integer)]')
                        continue
                    if up_nums == 0 or down_nums == 0:
                        logs['swarm']['validations']['responser_configuration'].append('All scaling configuration number must greater than 0')
                        continue
                    if current_nums == 0:
                        logs['swarm']['validations']['current_nums'].append('"current_nums" must greater than 0')
                        continue
                    if up_nums <= current_nums or down_nums >= up_nums or down_nums < current_nums:
                        logs['swarm']['validations']['responser_configuration'].append('"up_nums" must be greater than ["current_nums", "down_nums"] and "down_nums" must be greater than or equal ["current_nums"]')
                        continue
                    swarm_passed_list.append(swm)
                if swarm_passed_list.__len__() > 0:
                    try:
                        rabbitmq_response = get(
                            url=f'http://{RABBITMQ_HOST}:{RABBITMQ_MANAGEMENT_PORT}/api/healthchecks/node', 
                            auth=(
                                RABBITMQ_USERNAME, 
                                RABBITMQ_PASSWORD
                            )
                        )
                        if rabbitmq_response.status_code != 200:
                            logs['swarm']['others'].append(f'RabbitMQ healthcheck fail with HTTP status code {rabbitmq_response.status_code}')
                            is_error = True
                    except:
                        logs['swarm']['others'].append('Can\'t perform GET request to RabbitMQ for connection testing')
                        is_error = True
                    if is_error is False:
                        try:
                            prometheus_response = PrometheusConnect(url=f'{PROMETHEUS_HOST}:{PROMETHEUS_PORT}', disable_ssl=True)
                            if prometheus_response.check_prometheus_connection() is False:
                                logs['swarm']['others'].append('Prometheus check connection fail')
                                is_error = True
                        except:
                            logs['swarm']['others'].append('Can\'t perform check Prometheus for connection testing')
                            is_error = True
                    if is_error is False:
                        unique_id = uuid4()
                        runner = run(
                            private_data_dir=ANSIBLE_DATA_DIR,
                            module='ping',
                            inventory=ANSIBLE_INVENTORY,
                            extravars={
                                'username_swarm_node': ANSIBLE_SWARM_USERNAME,
                                'password_swarm_node': ANSIBLE_SWARM_PASSWORD,
                            },
                            host_pattern='swarm',
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
                            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id}', ignore_errors=True)
                            logs['swarm']['others'].append(error_message)
                            is_error = True
                    if is_error is False:
                        for swarm_passed in swarm_passed_list:
                            responser_name = swarm_passed.get('responser_name')
                            responser_configuration = self.normalize_string(text=swarm_passed.get('responser_configuration'))
                            current_nums = swarm_passed.get('current_nums')
                            response_elasticsearch.index(index='responser-swarm', document={
                                'responser_name': responser_name,
                                'responser_configuration': responser_configuration,
                                'current_nums': current_nums
                            }, refresh='wait_for')
                            response_elasticsearch.index(index='responser-swarm-executions', document={
                                'responser_name': responser_name,
                                'status': 'down',
                                'at_time': None,
                                'replicas': None,
                                'last_action': None,
                                'last_logs': None,
                            })
                            logs['swarm']['passed'].append(responser_name)
        return {
            'type': 'resources',
            'data': logs,
            'reason': 'Success'
        }
    
    def normalize_string(self, text: str) -> str:
        return sub(r'\s+', '', text).replace('\n', '').strip()

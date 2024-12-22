from flask import Blueprint, request
from ansible_runner import run
from datetime import datetime, timedelta
from json import dumps, loads
from ipaddress import ip_address
import re
from shutil import rmtree
import uuid
from .operations import iptables_operation_blueprint
from ..storage import response_elasticsearch, ES_MAX_RESULT, ANSIBLE_DATA_DIR, ANSIBLE_INVENTORY, ANSIBLE_FIREWALL_USERNAME, ANSIBLE_FIREWALL_PASSWORD
from ..functions import get_value_from_json, parse_path


iptables_main_blueprint = Blueprint(name='iptables_main_blueprint', import_name=__name__)

iptables_main_blueprint.register_blueprint(blueprint=iptables_operation_blueprint, url_prefix='/iptables')

iptables_responser_blueprint = Blueprint(name='iptables_responser_blueprint', import_name=__name__)

@iptables_responser_blueprint.route(rule='/iptables/<string:responser_name>', methods=['POST', 'GET'])
def iptables_responser_endpoint(responser_name: str):
    if response_elasticsearch.ping() is False:
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
    iptables = response_elasticsearch.search(index='responser-iptables', query={
        'term': {
            'responser_name.keyword': responser_name
        }
    }, size=ES_MAX_RESULT).raw
    if iptables['hits']['hits'].__len__() != 1:
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'NotFound: Responser Name is not found'
        }, 404
    if request.method == 'GET':
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'Success'
        }
    try:
        loads(request.data)
    except:
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'BadRequest: Body must be JSON'
        }, 400
    iptables_responser = iptables['hits']['hits'][0]
    try:
        responser_configuration = dict(loads(iptables_responser['_source']['responser_configuration']))
    except:
        response_elasticsearch.index(index='responser-iptables-errorlogs', document={
            'responser_name': responser_name,
            'message': 'Can\'t parse Responser Configuration for execution',
            'pattern': iptables_responser['_source']['responser_configuration']
        })
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'InternalServerError: Can\'t parse Responser Configuration for execution'
        }, 500
    is_enabled_configuration = responser_configuration.get('is_enabled')
    is_ruthless = responser_configuration.get('is_ruthless')
    target_ip_field = responser_configuration.get('target_ip_field')
    limit_duration_minutes = responser_configuration.get('limit_duration_minutes')
    block_duration_minutes = responser_configuration.get('block_duration_minutes')
    rate_limitation = dict(responser_configuration.get('rate_limitation'))
    advanced = dict(responser_configuration.get('advanced'))
    if is_enabled_configuration is False:
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'Success: This Responser is disabled'
        }
    request_body = request.get_json()
    target_ip_field_validation = parse_path(path=target_ip_field)
    if target_ip_field_validation is None or not isinstance(target_ip_field_validation, str):
        response_elasticsearch.index(index='responser-iptables-errorlogs', document={
            'responser_name': responser_name,
            'message': 'Invalid format of "target_ip_field"',
            'pattern': target_ip_field
        })
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'BadRequest: Invalid format of "target_ip_field"'
        }, 400
    target_ip_value = get_value_from_json(data=request_body, path=target_ip_field)
    if target_ip_value is None or not isinstance(target_ip_value, str):
        response_elasticsearch.index(index='responser-iptables-errorlogs', document={
            'responser_name': responser_name,
            'message': 'Value of "target_ip_field" is (null)',
            'pattern': target_ip_field
        })
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'BadRequest: Value of "target_ip_field" is (null)'
        }, 400
    try:
        ip_address(target_ip_value)
    except:
        response_elasticsearch.index(index='responser-iptables-errorlogs', document={
            'responser_name': responser_name,
            'message': '"target_ip_field" is not a valid IP',
            'pattern': target_ip_value
        })
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'NotAcceptable: "target_ip_field" is not a valid IP'
        }, 406
    is_enabled_advanced = advanced.get('is_enabled')
    threshold = advanced.get('threshold')
    time_window_seconds = advanced.get('time_window_seconds')
    if is_enabled_advanced is True:
        iptables_execution = response_elasticsearch.search(index='responser-iptables-executions', query={
            'bool': {
                'must': [
                    {'term': {
                        'responser_name.keyword': responser_name
                    }},
                    {'term': {
                        'target_ip_field.keyword': target_ip_value
                    }}
                ]
            }
        }, size=ES_MAX_RESULT).raw
        if iptables_execution['hits']['hits'].__len__() == 0:
            timestamp = datetime.now().timestamp()
            iptables_timestamp = response_elasticsearch.index(index='responser-iptables-timestamps', document={
                'responser_name': responser_name,
                'timestamp': int(timestamp),
                'target_ip_field': target_ip_value
            })
            iptables_timestamps = response_elasticsearch.search(index='responser-iptables-timestamps', query={
                'bool': {
                    'must': [
                        {'term': {
                            'responser_name.keyword': responser_name,
                        }},
                        {'term': {
                            'target_ip_field.keyword': target_ip_value
                        }}
                    ]
                }
            }, size=ES_MAX_RESULT).raw
            start_time = timestamp - time_window_seconds
            range_threshold = [iptables_timestamp['_source']['timestamp'] for iptables_timestamp in iptables_timestamps['hits']['hits'] if start_time <= iptables_timestamp['_source']['timestamp'] <= timestamp]
            if range_threshold.__len__() == 0:
                response_elasticsearch.delete_by_query(index='responser-iptables-timestamps', query={
                    'bool': {
                        'must_not': [
                            {'term': {'_id': iptables_timestamp['_id']}},
                            {'term': {'responser_name.keyword': responser_name}},
                            {'term': {'timestamp': int(timestamp)}},
                            {'term': {'target_ip_field.keyword': target_ip_value}}
                        ]
                    }
                })
            if range_threshold.__len__() < threshold:
                return {
                    'type': 'iptables_responser',
                    'data': None,
                    'reason': 'Success'
                }
    if is_ruthless is True:
        unique_id_ruthless_iptables = uuid.uuid4()
        ruthless_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/iptables/playbooks/ansible_apply_third_iptables.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'source_ip': target_ip_value,
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_ruthless_iptables
        )
        if ruthless_runner.rc != 0:
            response_elasticsearch.index(index='responser-iptables-errorlogs', document={
                'responser_name': responser_name,
                'message': '"ansible_apply_third_iptables.yaml" can\'t run',
                'pattern': 'api/iptables/playbooks/ansible_apply_third_iptables.yaml'
            })
            return {
                'type': 'iptables_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_third_iptables.yaml" can\'t run'
            }, 500
        time = datetime.now() + timedelta(hours=7)
        response_elasticsearch.index(index='responser-iptables-executions', document={
            'responser_name': responser_name,
            'target_ip_field': target_ip_value,
            'state': 'forever',
            'start': f'{time.hour}:{time.minute}:{time.second} {time.day}/{time.month}/{time.year}',
            'finish': None,
            'payload': dumps(request_body),
            'timestamp': int(time.timestamp()),
            'end_at': None
        })
        response_elasticsearch.update(index='responser-iptables', id=iptables_responser['_id'], doc={
            'responser_configuration': dumps({
                {
                    'is_enabled': False, 
                    'target_ip_field': target_ip_field, 
                    'is_ruthless': is_ruthless, 
                    'limit_duration_minutes': limit_duration_minutes, 
                    'rate_limitation': {
                        'packet_nums': rate_limitation.get('packet_nums'), 
                        'duration_type': rate_limitation.get('duration_type'), 
                        'burst': rate_limitation.get('burst')
                    }, 
                    'block_duration_minutes': block_duration_minutes, 
                    'advanced': {
                        'is_enabled': is_enabled_advanced, 
                        'threshold': threshold, 
                        'time_window_seconds': time_window_seconds
                    }
                }
            })
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_ruthless_iptables}', ignore_errors=True)
    unique_id_list_iptables = uuid.uuid4()
    runner = run(
        private_data_dir=ANSIBLE_DATA_DIR,
        playbook='../api/iptables/playbooks/ansible_list_iptables.yaml',
        inventory=ANSIBLE_INVENTORY,
        extravars={
            'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
            'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD
        },
        host_pattern='firewall',
        json_mode=True,
        quiet=True,
        ident=unique_id_list_iptables
    )
    related_rules = []
    if runner.rc != 0:
        response_elasticsearch.index(index='responser-iptables-errorlogs', document={
            'responser_name': responser_name,
            'message': '"ansible_list_iptables.yaml" can\'t run',
            'pattern': 'api/iptables/playbooks/ansible_list_iptables.yaml'
        })
        return {
            'type': 'iptables_responser',
            'data': None,
            'reason': 'InternalServerError: "ansible_list_iptables.yaml" can\'t run'
        }, 500
    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            related_rules = event['event_data']['res']['stdout_lines']
    
    pattern = r'DOCKER-USER -s (\d+\.\d+\.\d+\.\d+(?:/\d+)?) (.+)'

    related_rule_matches = []
    for related_rule in related_rules:
        match = re.search(pattern, related_rule)
        if match:
            related_rule_matches.append(related_rule)
    target_rules = []
    for relatd_rule_match in related_rule_matches:
        if target_ip_value in relatd_rule_match:
            target_rules.append(relatd_rule_match)
    level_apply = 0
    is_first_apply = False
    is_second_apply = False
    is_third_apply = False
    for target_rule in target_rules:
        if 'hashlimit' in target_rule:
            is_first_apply = True
        elif 'comment' in target_rule:
            is_second_apply = True
        else:
            is_third_apply = True
    if is_first_apply is True:
        level_apply = 1
    if is_second_apply is True:
        level_apply = 2
    if is_third_apply is True:
        level_apply = 3
    if level_apply == 0:
        packet_nums = rate_limitation.get('packet_nums')
        duration_type = rate_limitation.get('duration_type')
        burst = rate_limitation.get('burst')
        unique_id_first_apply_iptables = uuid.uuid4()
        first_apply_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/iptables/playbooks/ansible_apply_first_iptables.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'source_ip': target_ip_value,
                'hashlimit_name': f'http_limit_{unique_id_first_apply_iptables}',
                'packet_nums': packet_nums,
                'duration_type': duration_type,
                'burst': burst,
                'limit_duration_minutes': limit_duration_minutes
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_first_apply_iptables
        )
        if first_apply_runner.rc != 0:
            response_elasticsearch.index(index='responser-iptables-errorlogs', document={
                'responser_name': responser_name,
                'message': '"ansible_apply_first_iptables.yaml" can\'t run',
                'pattern': 'api/iptables/playbooks/ansible_apply_first_iptables.yaml'
            })
            return {
                'type': 'iptables_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_first_iptables.yaml" can\'t run'
            }, 500
        # response_elasticsearch.delete_by_query(index='responser-iptables-executions', query={
        #     'bool': {
        #         'must': [
        #             {'term': {
        #                 'responser_name.keyword': responser_name
        #             }},
        #             {'term': {
        #                 'target_ip_field.keyword': target_ip_value,
        #             }},
        #             {'term': {
        #                 'state.keyword': 'limitation'
        #             }}
        #         ]
        #     }
        # })
        # response_elasticsearch.delete_by_query(index='responser-iptables-executions', query={
        #     'bool': {
        #         'must': [
        #             {'term': {
        #                 'responser_name.keyword': responser_name
        #             }},
        #             {'term': {
        #                 'target_ip_field.keyword': target_ip_value,
        #             }},
        #             {'term': {
        #                 'state.keyword': 'temporary'
        #             }}
        #         ]
        #     }
        # })
        time = datetime.now() + timedelta(hours=7)
        end = time + timedelta(minutes=limit_duration_minutes)
        response_elasticsearch.index(index='responser-iptables-executions', document={
            'responser_name': responser_name,
            'target_ip_field': target_ip_value,
            'state': 'limitation',
            'start': f'{time.hour}:{time.minute}:{time.second} {time.day}/{time.month}/{time.year}',
            'finish': f'{end.hour}:{end.minute}:{end.second} {end.day}/{end.month}/{end.year}',
            'payload': dumps(request_body),
            'timestamp': int(time.timestamp()),
            'end_at': int(end.timestamp())
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_first_apply_iptables}', ignore_errors=True)
    if level_apply == 1:
        unique_id_second_apply_iptables = uuid.uuid4()
        second_apply_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/iptables/playbooks/ansible_apply_second_iptables.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'source_ip': target_ip_value,
                'block_duration_minutes': block_duration_minutes
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_second_apply_iptables
        )
        if second_apply_runner.rc != 0:
            response_elasticsearch.index(index='responser-iptables-errorlogs', document={
                'responser_name': responser_name,
                'message': '"ansible_apply_second_iptables.yaml" can\'t run',
                'pattern': 'api/iptables/playbooks/ansible_apply_second_iptables.yaml'
            })
            return {
                'type': 'iptables_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_second_iptables.yaml" can\'t run'
            }, 500
        # response_elasticsearch.delete_by_query(index='responser-iptables-executions', query={
        #     'bool': {
        #         'must': [
        #             {'term': {
        #                 'responser_name.keyword': responser_name
        #             }},
        #             {'term': {
        #                 'target_ip_field.keyword': target_ip_value,
        #             }},
        #             {'term': {
        #                 'state.keyword': 'limitation'
        #             }}
        #         ]
        #     }
        # })
        time = datetime.now() + timedelta(hours=7)
        end = time + timedelta(minutes=block_duration_minutes)
        response_elasticsearch.index(index='responser-iptables-executions', document={
            'responser_name': responser_name,
            'target_ip_field': target_ip_value,
            'state': 'temporary',
            'start': f'{time.hour}:{time.minute}:{time.second} {time.day}/{time.month}/{time.year}',
            'finish': f'{end.hour}:{end.minute}:{end.second} {end.day}/{end.month}/{end.year}',
            'payload': dumps(request_body),
            'timestamp': int(time.timestamp()),
            'end_at': int(end.timestamp())
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_second_apply_iptables}', ignore_errors=True)
    if level_apply == 2:
        unique_id_third_apply_iptables = uuid.uuid4()
        third_apply_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/iptables/playbooks/ansible_apply_third_iptables.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'source_ip': target_ip_value,
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_third_apply_iptables
        )
        if third_apply_runner.rc != 0:
            response_elasticsearch.index(index='responser-iptables-errorlogs', document={
                'responser_name': responser_name,
                'message': '"ansible_apply_third_iptables.yaml" can\'t run',
                'pattern': 'api/iptables/playbooks/ansible_apply_third_iptables.yaml'
            })
            return {
                'type': 'iptables_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_third_iptables.yaml" can\'t run'
            }, 500
        # response_elasticsearch.delete_by_query(index='responser-iptables-executions', query={
        #     'bool': {
        #         'must': [
        #             {'term': {
        #                 'responser_name.keyword': responser_name
        #             }},
        #             {'term': {
        #                 'target_ip_field.keyword': target_ip_value,
        #             }},
        #             {'term': {
        #                 'state.keyword': 'temporary'
        #             }}
        #         ]
        #     }
        # })
        time = datetime.now() + timedelta(hours=7)
        response_elasticsearch.index(index='responser-iptables-executions', document={
            'responser_name': responser_name,
            'target_ip_field': target_ip_value,
            'state': 'forever',
            'start': f'{time.hour}:{time.minute}:{time.second} {time.day}/{time.month}/{time.year}',
            'finish': None,
            'payload': dumps(request_body),
            'timestamp': int(time.timestamp()),
            'end_at': None
        })
        response_elasticsearch.update(index='responser-iptables', id=iptables_responser['_id'], doc={
            'responser_configuration': dumps({
                {
                    'is_enabled': False, 
                    'target_ip_field': target_ip_field, 
                    'is_ruthless': is_ruthless, 
                    'limit_duration_minutes': limit_duration_minutes, 
                    'rate_limitation': {
                        'packet_nums': rate_limitation.get('packet_nums'), 
                        'duration_type': rate_limitation.get('duration_type'), 
                        'burst': rate_limitation.get('burst')
                    }, 
                    'block_duration_minutes': block_duration_minutes, 
                    'advanced': {
                        'is_enabled': is_enabled_advanced, 
                        'threshold': threshold, 
                        'time_window_seconds': time_window_seconds
                    }
                }
            })
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_third_apply_iptables}', ignore_errors=True)
    rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_list_iptables}', ignore_errors=True)
    return {
        'type': 'iptables_responser',
        'data': None,
        'reason': 'Success'
    }

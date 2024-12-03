from flask import Blueprint, request
from ansible_runner import run
from datetime import datetime, timedelta
from ipaddress import ip_address as validate_ip_address
from json import dumps, loads
import re
from shutil import rmtree
import uuid
from .operations import modsecurity_operation_blueprint
from ..functions import get_value_from_json, generate_full_regex
from ..storage import (
    response_elasticsearch, 
    ES_MAX_RESULT, 
    ANSIBLE_DATA_DIR, 
    ANSIBLE_INVENTORY, 
    ANSIBLE_FIREWALL_USERNAME, 
    ANSIBLE_FIREWALL_PASSWORD, 
    ANSIBLE_CRS_PATH_DIR, 
    ANSIBLE_MODSEC_CONAME
)


modsecurity_main_blueprint = Blueprint(name='modsecurity_main_blueprint', import_name=__name__)

modsecurity_main_blueprint.register_blueprint(blueprint=modsecurity_operation_blueprint, url_prefix='/modsecurity')

modsecurity_responser_blueprint = Blueprint(name='modsecurity_responser_blueprint', import_name=__name__)

@modsecurity_responser_blueprint.route(rule='/modsecurity/<string:responser_name>', methods=['GET', 'POST'])
def modsecurity_responser_endpoint(responser_name: str):
    if response_elasticsearch.ping() is False:
        return {
            'type': 'modsecurity_responser',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
    modsecurity = response_elasticsearch.search(index='responser-modsecurity', query={
        'term': {
            'responser_name.keyword': responser_name
        }
    }, size=ES_MAX_RESULT).raw
    if modsecurity['hits']['hits'].__len__() != 1:
        return {
            'type': 'modsecurity_responser',
            'data': None,
            'reason': 'NotFound: Responser Name is not found'
        }, 404
    if request.method == 'GET':
        return {
            'type': 'modsecurity_responser',
            'data': None,
            'reason': 'Success'
        }
    try:
        loads(request.data)
    except:
        return {
            'type': 'modsecurity_responser',
            'data': None,
            'reason': 'BadRequest: Body must be JSON'
        }, 400
    modsecurity_configuration: dict = loads(modsecurity['hits']['hits'][0]['_source'].get('responser_configuration'))
    configuration_is_enabled = modsecurity_configuration.get('is_enabled')
    ip_address = modsecurity_configuration.get('ip_address')
    payload = modsecurity_configuration.get('payload')
    advanced = modsecurity_configuration.get('advanced')
    if configuration_is_enabled is False:
        return {
            'type': 'modsecurity_responser',
            'data': None,
            'reason': 'Success: This Responser is disabled'
        }
    is_ip_address: dict = ip_address.get('is_used')
    is_payload: dict = payload.get('is_used')
    is_advanced: dict = advanced.get('is_enabled')
    getted_ip_address = False; getted_rule = False; getted_payload = False
    ip_source_value = None; regex_value = None
    full_regex = None; root_cause_value = None
    modsecurity_execution_for_ip = None
    modsecurity_execution_for_chain = None
    modsecurity_execution = None
    id_for_secrule_ip = 1
    id_for_secrule_chain = 2
    id_for_secrule = 1
    request_body: dict = request.get_json()
    if is_ip_address is True:
        ip_source_value = get_value_from_json(data=request_body, path=ip_address.get('ip_source_field'))
        if ip_source_value is None:
            response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                'responser_name': responser_name,
                'message': '"ip_source_field" not found',
                'pattern': ip_address.get('ip_source_field')
            })
        else:
            try:
                ip_source_value = str(validate_ip_address(address=ip_source_value))
                getted_ip_address = True
            except:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"ip_source_field" field not a valid IP',
                    'pattern': ip_address.get('ip_source_field')
                })
    if is_payload is True:
        root_cause_value = get_value_from_json(data=request_body, path=payload.get('root_cause_field'))
        if root_cause_value is None or root_cause_value.__len__() == 0:
            response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                'responser_name': responser_name,
                'message': '"root_cause_field" not found',
                'pattern': payload.get('root_cause_field')
            })
        else:
            root_cause_value = str(root_cause_value)
            getted_payload = True

        regex_value = get_value_from_json(data=request_body, path=payload.get('regex_field'))
        if regex_value is None or regex_value.__len__() == 0:
            response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                'responser_name': responser_name,
                'message': '"regex_field" not found',
                'pattern': payload.get('regex_field')
            })
        else:
            try:
                regex_value = re.compile(regex_value)
                getted_rule = True
            except:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"regex_field" field not a valid ReGex',
                    'pattern': payload.get('regex_field')
                })
        if getted_payload is True and getted_rule is True:
            try:
                full_regex = generate_full_regex(text=root_cause_value, sub_regex=regex_value.pattern)
                full_regex = re.sub(r'\\\s+', r'\\s*', full_regex)
            except:
                full_regex = regex_value.pattern
            if re.fullmatch(full_regex, root_cause_value) is None:
                getted_rule = False
    if getted_ip_address is False and getted_rule is False and getted_payload is False:
        response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
            'responser_name': responser_name,
            'message': 'Can\'t get ["ip_source_field", "regex_field", "root_cause_field"]',
            'pattern': None
        })
        return {
            'type': 'modsecurity_responser',
            'data': None,
            'reason': 'Success: The body of this request is invalid, logged'
        }
    if is_advanced is True:
        threshold = advanced.get('threshold')
        time_window_seconds = advanced.get('time_window_seconds')
        if getted_ip_address is True:
            modsecurity_checking_execution = response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'bool': {
                    'must': [
                        {'term': {
                            'responser_name.keyword': responser_name
                        }},
                        {'term': {
                            'detail_ip.keyword': ip_source_value
                        }}
                    ]
                }
            }, size=ES_MAX_RESULT).raw
            if modsecurity_checking_execution['hits']['hits'].__len__() == 0:
                timestamp = datetime.now().timestamp()
                modsecurity_timestamp = response_elasticsearch.index(index='responser-modsecurity-timestamps', document={
                    'responser_name': responser_name,
                    'timestamp': int(timestamp),
                    'detail_ip': ip_source_value
                })
                modsecurity_timestamps = response_elasticsearch.search(index='responser-modsecurity-timestamps', query={
                    'bool': {
                        'must': [
                            {'term': {
                                'responser_name.keyword': responser_name,
                            }},
                            {'term': {
                                'detail_ip.keyword': ip_source_value
                            }}
                        ]
                    }
                }, size=ES_MAX_RESULT).raw
                start_time = timestamp - time_window_seconds
                range_threshold = [modsecurity_timestamp['_source']['timestamp'] for modsecurity_timestamp in modsecurity_timestamps['hits']['hits'] if start_time <= modsecurity_timestamp['_source']['timestamp'] <= timestamp]
                if range_threshold.__len__() == 0:
                    response_elasticsearch.delete_by_query(index='responser-modsecurity-timestamps', query={
                        'bool': {
                            'must_not': [
                                {'term': {'_id': modsecurity_timestamp['_id']}},
                                {'term': {'responser_name.keyword': responser_name}},
                                {'term': {'timestamp': int(timestamp)}},
                                {'term': {'detail_ip.keyword': ip_source_value}}
                            ]
                        }
                    })
                if range_threshold.__len__() < threshold:
                    return {
                        'type': 'modsecurity_responser',
                        'data': None,
                        'reason': 'Success'
                    }
        elif getted_rule is True:
            modsecurity_checking_execution = response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'bool': {
                    'must': [
                        {'term': {
                            'responser_name.keyword': responser_name
                        }},
                        {'term': {
                            'detail_rule.keyword': regex_value.pattern if full_regex is None else full_regex
                        }}
                    ]
                }
            }, size=ES_MAX_RESULT).raw
            if modsecurity_checking_execution['hits']['hits'].__len__() == 0:
                timestamp = datetime.now().timestamp()
                modsecurity_timestamp = response_elasticsearch.index(index='responser-modsecurity-timestamps', document={
                    'responser_name': responser_name,
                    'timestamp': int(timestamp),
                    'detail_rule': regex_value.pattern if full_regex is None else full_regex
                })
                modsecurity_timestamps = response_elasticsearch.search(index='responser-modsecurity-timestamps', query={
                    'bool': {
                        'must': [
                            {'term': {
                                'responser_name.keyword': responser_name,
                            }},
                            {'term': {
                                'detail_rule.keyword': regex_value.pattern if full_regex is None else full_regex
                            }}
                        ]
                    }
                }, size=ES_MAX_RESULT).raw
                start_time = timestamp - time_window_seconds
                range_threshold = [modsecurity_timestamp['_source']['timestamp'] for modsecurity_timestamp in modsecurity_timestamps['hits']['hits'] if start_time <= modsecurity_timestamp['_source']['timestamp'] <= timestamp]
                if range_threshold.__len__() == 0:
                    response_elasticsearch.delete_by_query(index='responser-modsecurity-timestamps', query={
                        'bool': {
                            'must_not': [
                                {'term': {'_id': modsecurity_timestamp['_id']}},
                                {'term': {'responser_name.keyword': responser_name}},
                                {'term': {'timestamp': int(timestamp)}},
                                {'term': {'detail_rule.keyword': regex_value.pattern if full_regex is None else full_regex}}
                            ]
                        }
                    })
                if range_threshold.__len__() < threshold:
                    return {
                        'type': 'modsecurity_responser',
                        'data': None,
                        'reason': 'Success'
                    }
        elif getted_payload is True:
            modsecurity_checking_execution = response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'bool': {
                    'must': [
                        {'term': {
                            'responser_name.keyword': responser_name
                        }},
                        {'term': {
                            'detail_payload.keyword': root_cause_value
                        }}
                    ]
                }
            }, size=ES_MAX_RESULT).raw
            if modsecurity_checking_execution['hits']['hits'].__len__() == 0:
                timestamp = datetime.now().timestamp()
                modsecurity_timestamp = response_elasticsearch.index(index='responser-modsecurity-timestamps', document={
                    'responser_name': responser_name,
                    'timestamp': int(timestamp),
                    'detail_payload': root_cause_value
                })
                modsecurity_timestamps = response_elasticsearch.search(index='responser-modsecurity-timestamps', query={
                    'bool': {
                        'must': [
                            {'term': {
                                'responser_name.keyword': responser_name,
                            }},
                            {'term': {
                                'detail_payload.keyword': root_cause_value
                            }}
                        ]
                    }
                }, size=ES_MAX_RESULT).raw
                start_time = timestamp - time_window_seconds
                range_threshold = [modsecurity_timestamp['_source']['timestamp'] for modsecurity_timestamp in modsecurity_timestamps['hits']['hits'] if start_time <= modsecurity_timestamp['_source']['timestamp'] <= timestamp]
                if range_threshold.__len__() == 0:
                    response_elasticsearch.delete_by_query(index='responser-modsecurity-timestamps', query={
                        'bool': {
                            'must_not': [
                                {'term': {'_id': modsecurity_timestamp['_id']}},
                                {'term': {'responser_name.keyword': responser_name}},
                                {'term': {'timestamp': int(timestamp)}},
                                {'term': {'detail_payload.keyword': root_cause_value}}
                            ]
                        }
                    })
                if range_threshold.__len__() < threshold:
                    return {
                        'type': 'modsecurity_responser',
                        'data': None,
                        'reason': 'Success'
                    }
    modsecurity_executions = response_elasticsearch.search(index='responser-modsecurity-executions', query={
        'match_all': {}
    }, size=ES_MAX_RESULT).raw
    if getted_ip_address is True and getted_rule is True and getted_payload is True:
        if modsecurity_executions['hits']['hits'].__len__() > 0:
            id_for_secrule_ip = modsecurity_executions['hits']['hits'].__len__() + 1
            id_for_secrule_chain = modsecurity_executions['hits']['hits'].__len__() + 2
            if id_for_secrule_ip > 799999 or id_for_secrule_chain > 799999:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"id_for_secrule_ip" or "id_for_secrule_chain" exceeded the limit (maximum is 799999)',
                    'pattern': None
                })
                return {
                    'type': 'modsecurity_responser',
                    'data': None,
                    'reason': 'Success: Responser will stop execution because SecRule ID exceeded the limit (maximum is 799999), logged'
                }
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule_ip
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution_for_ip = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule_ip,
                    'type': 'full',
                    'for': 'ip',
                    'start': None,
                    'detail_ip': ip_source_value,
                    'detail_rule': full_regex,
                    'detail_payload': root_cause_value,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule_ip += 1
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule_chain
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution_for_chain = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule_chain,
                    'type': 'full',
                    'for': 'chain',
                    'start': None,
                    'detail_ip': ip_source_value,
                    'detail_rule': full_regex,
                    'detail_payload': root_cause_value,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule_chain += 1
        unique_id_full_forever = uuid.uuid4()
        full_forever_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/modsecurity/playbooks/ansible_apply_full_modsecurity.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'secrule_anomaly_score': ip_address.get('anomaly_score'),
                'secrule_paranoia_level': ip_address.get('paranoia_level'),
                'secrule_regex': full_regex.replace('"', '\\\"').replace('\\b', '@backspace@'),
                'secrule_id_ip': id_for_secrule_ip,
                'secrule_id_chain': id_for_secrule_chain,
                'secrule_ip': ip_source_value,
                'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{id_for_secrule_ip}-{id_for_secrule_chain}-{unique_id_full_forever}',
                'modsec_container_name': ANSIBLE_MODSEC_CONAME
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_full_forever
        )
        if full_forever_runner.rc != 0:
            for event in full_forever_runner.events:
                if event.get('event') == 'runner_on_failed':
                    if event['event_data'].get('task') == 'fail':
                        response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                            'responser_name': responser_name,
                            'message': event['stdout'],
                            'pattern': 'api/modsecurity/playbooks/ansible_apply_full_modsecurity.yaml'
                        })
                        break
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_full_forever}', ignore_errors=True)
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution_for_ip['_id'])
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution_for_chain['_id'])
            return {
                'type': 'modsecurity_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_full_modsecurity.yaml" can\'t run'
            }, 500
        time_now = datetime.now() + timedelta(hours=7)
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution_for_ip['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
            'relationship': id_for_secrule_chain,
            'real_id_relationship': modsecurity_execution_for_chain['_id']
        })
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution_for_chain['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
            'relationship': id_for_secrule_ip,
            'real_id_relationship': modsecurity_execution_for_ip['_id']
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_full_forever}', ignore_errors=True)
    if getted_ip_address is False and getted_rule is True and getted_payload is True:
        if modsecurity_executions['hits']['hits'].__len__() > 0:
            id_for_secrule = modsecurity_executions['hits']['hits'].__len__() + 1
            if id_for_secrule > 799999:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"id_for_secrule" exceeded the limit (maximum is 799999)',
                    'pattern': None
                })
                return {
                    'type': 'modsecurity_responser',
                    'data': None,
                    'reason': 'Success: Responser will stop execution because SecRule ID exceeded the limit (maximum is 799999), logged'
                }
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule,
                    'type': 'onlyRegexAndPayload',
                    'for': None,
                    'start': None,
                    'detail_ip': None,
                    'detail_rule': full_regex,
                    'detail_payload': root_cause_value,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule += 1
        unique_id_onlyRegexAndPayload_forever = uuid.uuid4()
        onlyRegexAndPayload_forever_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/modsecurity/playbooks/ansible_apply_only_regex_payload_modsecurity.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'secrule_regex': full_regex.replace('"', '\\\"').replace('\\b', '@backspace@'),
                'secrule_id': id_for_secrule,
                'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{id_for_secrule}-{unique_id_onlyRegexAndPayload_forever}',
                'modsec_container_name': ANSIBLE_MODSEC_CONAME
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_onlyRegexAndPayload_forever
        )
        if onlyRegexAndPayload_forever_runner.rc != 0:
            for event in onlyRegexAndPayload_forever_runner.events:
                if event.get('event') == 'runner_on_failed':
                    if event['event_data'].get('task') == 'fail':
                        response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                            'responser_name': responser_name,
                            'message': event['stdout'],
                            'pattern': 'api/modsecurity/playbooks/ansible_apply_only_regex_payload_modsecurity.yaml'
                        })
                        break
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyRegexAndPayload_forever}', ignore_errors=True)
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution['_id'])
            return {
                'type': 'modsecurity_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_only_regex_payload_modsecurity.yaml" can\'t run'
            }, 500
        time_now = datetime.now() + timedelta(hours=7)
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyRegexAndPayload_forever}', ignore_errors=True)
    if getted_ip_address is False and getted_rule is False and getted_payload is True:
        if modsecurity_executions['hits']['hits'].__len__() > 0:
            id_for_secrule = modsecurity_executions['hits']['hits'].__len__() + 1
            if id_for_secrule > 799999:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"id_for_secrule" exceeded the limit (maximum is 799999)',
                    'pattern': None
                })
                return {
                    'type': 'modsecurity_responser',
                    'data': None,
                    'reason': 'Success: Responser will stop execution because SecRule ID exceeded the limit (maximum is 799999), logged'
                }
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule,
                    'type': 'onlyPayload',
                    'for': None,
                    'start': None,
                    'detail_ip': None,
                    'detail_rule': None,
                    'detail_payload': root_cause_value,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule += 1
        unique_id_onlyPayload_forever = uuid.uuid4()
        onlyPayload_forever_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/modsecurity/playbooks/ansible_apply_only_payload_modsecurity.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'secrule_payload': root_cause_value.replace('\"', '\\\"'),
                'secrule_id': id_for_secrule,
                'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{id_for_secrule}-{unique_id_onlyPayload_forever}',
                'modsec_container_name': ANSIBLE_MODSEC_CONAME
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_onlyPayload_forever
        )
        if onlyPayload_forever_runner.rc != 0:
            for event in onlyPayload_forever_runner.events:
                if event.get('event') == 'runner_on_failed':
                    if event['event_data'].get('task') == 'fail':
                        response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                            'responser_name': responser_name,
                            'message': event['stdout'],
                            'pattern': 'api/modsecurity/playbooks/ansible_apply_only_payload_modsecurity.yaml'
                        })
                        break
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyPayload_forever}', ignore_errors=True)
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution['_id'])
            return {
                'type': 'modsecurity_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_only_payload_modsecurity.yaml" can\'t run'
            }, 500
        time_now = datetime.now() + timedelta(hours=7)
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyPayload_forever}', ignore_errors=True)
    if getted_ip_address is True and getted_rule is False and getted_payload is False:
        if modsecurity_executions['hits']['hits'].__len__() > 0:
            id_for_secrule = modsecurity_executions['hits']['hits'].__len__() + 1
            if id_for_secrule > 799999:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"id_for_secrule" exceeded the limit (maximum is 799999)',
                    'pattern': None
                })
                return {
                    'type': 'modsecurity_responser',
                    'data': None,
                    'reason': 'Success: Responser will stop execution because SecRule ID exceeded the limit (maximum is 799999), logged'
                }
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule,
                    'type': 'onlyIP',
                    'for': None,
                    'start': None,
                    'detail_ip': ip_source_value,
                    'detail_rule': None,
                    'detail_payload': None,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule += 1
        unique_id_onlyIP_forever = uuid.uuid4()
        onlyIP_forever_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/modsecurity/playbooks/ansible_apply_only_ip_modsecurity.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'secrule_ip': ip_source_value,
                'secrule_id': id_for_secrule,
                'secrule_anomaly_score': ip_address.get('anomaly_score'),
                'secrule_paranoia_level': ip_address.get('paranoia_level'),
                'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{id_for_secrule}-{unique_id_onlyIP_forever}',
                'modsec_container_name': ANSIBLE_MODSEC_CONAME
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_onlyIP_forever
        )
        if onlyIP_forever_runner.rc != 0:
            for event in onlyIP_forever_runner.events:
                if event.get('event') == 'runner_on_failed':
                    if event['event_data'].get('task') == 'fail':
                        response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                            'responser_name': responser_name,
                            'message': event['stdout'],
                            'pattern': 'api/modsecurity/playbooks/ansible_apply_only_ip_modsecurity.yaml'
                        })
                        break
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyIP_forever}', ignore_errors=True)
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution['_id'])
            return {
                'type': 'modsecurity_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_only_ip_modsecurity.yaml" can\'t run'
            }, 500
        time_now = datetime.now() + timedelta(hours=7)
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyIP_forever}', ignore_errors=True)
    if getted_ip_address is True and getted_rule is True and getted_payload is False:
        if modsecurity_executions['hits']['hits'].__len__() > 0:
            id_for_secrule_ip = modsecurity_executions['hits']['hits'].__len__() + 1
            id_for_secrule_chain = modsecurity_executions['hits']['hits'].__len__() + 2
            if id_for_secrule_ip > 799999 or id_for_secrule_chain > 799999:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"id_for_secrule_ip" or "id_for_secrule_chain" exceeded the limit (maximum is 799999)',
                    'pattern': None
                })
                return {
                    'type': 'modsecurity_responser',
                    'data': None,
                    'reason': 'Success: Responser will stop execution because SecRule ID exceeded the limit (maximum is 799999), logged'
                }
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule_ip
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution_for_ip = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule_ip,
                    'type': 'onlyIPAndRegex',
                    'for': 'ip',
                    'start': None,
                    'detail_ip': ip_source_value,
                    'detail_rule': regex_value.pattern,
                    'detail_payload': None,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule_ip += 1
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule_chain
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution_for_chain = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule_chain,
                    'type': 'onlyIPAndRegex',
                    'for': 'chain',
                    'start': None,
                    'detail_ip': ip_source_value,
                    'detail_rule': regex_value.pattern,
                    'detail_payload': None,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule_chain += 1
        unique_id_onlyIPAndRegex_forever = uuid.uuid4()
        onlyIPAndRegex_forever_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/modsecurity/playbooks/ansible_apply_only_ip_regex_modsecurity.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'secrule_anomaly_score': ip_address.get('anomaly_score'),
                'secrule_paranoia_level': ip_address.get('paranoia_level'),
                'secrule_regex': regex_value.pattern.replace('"', '\\\"').replace('\\b', '@backspace@'),
                'secrule_id_ip': id_for_secrule_ip,
                'secrule_id_chain': id_for_secrule_chain,
                'secrule_ip': ip_source_value,
                'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{id_for_secrule_ip}-{id_for_secrule_chain}-{unique_id_onlyIPAndRegex_forever}',
                'modsec_container_name': ANSIBLE_MODSEC_CONAME
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_onlyIPAndRegex_forever
        )
        if onlyIPAndRegex_forever_runner.rc != 0:
            for event in onlyIPAndRegex_forever_runner.events:
                if event.get('event') == 'runner_on_failed':
                    if event['event_data'].get('task') == 'fail':
                        response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                            'responser_name': responser_name,
                            'message': event['stdout'],
                            'pattern': 'api/modsecurity/playbooks/ansible_apply_only_ip_regex_modsecurity.yaml'
                        })
                        break
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyIPAndRegex_forever}', ignore_errors=True)
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution_for_ip['_id'])
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution_for_chain['_id'])
            return {
                'type': 'modsecurity_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_only_ip_regex_modsecurity.yaml" can\'t run'
            }, 500
        time_now = datetime.now() + timedelta(hours=7)
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution_for_ip['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
            'relationship': id_for_secrule_chain,
            'real_id_relationship': modsecurity_execution_for_chain['_id']
        })
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution_for_chain['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
            'relationship': id_for_secrule_ip,
            'real_id_relationship': modsecurity_execution_for_ip['_id']
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyIPAndRegex_forever}', ignore_errors=True)
    if getted_ip_address is False and getted_rule is True and getted_payload is False:
        if modsecurity_executions['hits']['hits'].__len__() > 0:
            id_for_secrule = modsecurity_executions['hits']['hits'].__len__() + 1
            if id_for_secrule > 799999:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"id_for_secrule" exceeded the limit (maximum is 799999)',
                    'pattern': None
                })
                return {
                    'type': 'modsecurity_responser',
                    'data': None,
                    'reason': 'Success: Responser will stop execution because SecRule ID exceeded the limit (maximum is 799999), logged'
                }
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule,
                    'type': 'onlyRegex',
                    'for': None,
                    'start': None,
                    'detail_ip': None,
                    'detail_rule': regex_value.pattern,
                    'detail_payload': None,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule += 1
        unique_id_onlyRegex_forever = uuid.uuid4()
        onlyRegex_forever_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/modsecurity/playbooks/ansible_apply_only_regex_modsecurity.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'secrule_regex': regex_value.pattern.replace('"', '\\\"').replace('\\b', '@backspace@'),
                'secrule_id': id_for_secrule,
                'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{id_for_secrule}-{unique_id_onlyRegex_forever}',
                'modsec_container_name': ANSIBLE_MODSEC_CONAME
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_onlyRegex_forever
        )
        if onlyRegex_forever_runner.rc != 0:
            for event in onlyRegex_forever_runner.events:
                if event.get('event') == 'runner_on_failed':
                    if event['event_data'].get('task') == 'fail':
                        response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                            'responser_name': responser_name,
                            'message': event['stdout'],
                            'pattern': 'api/modsecurity/playbooks/ansible_apply_only_regex_modsecurity.yaml'
                        })
                        break
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyRegex_forever}', ignore_errors=True)
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution['_id'])
            return {
                'type': 'modsecurity_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_only_regex_modsecurity.yaml" can\'t run'
            }, 500
        time_now = datetime.now() + timedelta(hours=7)
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyRegex_forever}', ignore_errors=True)
    if getted_ip_address is True and getted_rule is False and getted_payload is True:
        if modsecurity_executions['hits']['hits'].__len__() > 0:
            id_for_secrule_ip = modsecurity_executions['hits']['hits'].__len__() + 1
            id_for_secrule_chain = modsecurity_executions['hits']['hits'].__len__() + 2
            if id_for_secrule_ip > 799999 or id_for_secrule_chain > 799999:
                response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': '"id_for_secrule_ip" or "id_for_secrule_chain" exceeded the limit (maximum is 799999)',
                    'pattern': None
                })
                return {
                    'type': 'modsecurity_responser',
                    'data': None,
                    'reason': 'Success: Responser will stop execution because SecRule ID exceeded the limit (maximum is 799999), logged'
                }
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule_ip
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution_for_ip = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule_ip,
                    'type': 'onlyIPAndPayload',
                    'for': 'ip',
                    'start': None,
                    'detail_ip': ip_source_value,
                    'detail_rule': None,
                    'detail_payload': root_cause_value,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule_ip += 1
        while True:
            if response_elasticsearch.search(index='responser-modsecurity-executions', query={
                'term': {
                    'secrule_id': id_for_secrule_chain
                }
            }).raw['hits']['hits'].__len__() == 0:
                modsecurity_execution_for_chain = response_elasticsearch.index(index='responser-modsecurity-executions', document={
                    'responser_name': responser_name,
                    'secrule_id': id_for_secrule_chain,
                    'type': 'onlyIPAndPayload',
                    'for': 'chain',
                    'start': None,
                    'detail_ip': ip_source_value,
                    'detail_rule': None,
                    'detail_payload': root_cause_value,
                    'payload': dumps(request_body),
                    'relationship': None,
                    'real_id_relationship': None
                }).raw
                break
            id_for_secrule_chain += 1
        unique_id_onlyIPAndPayload_forever = uuid.uuid4()
        onlyIPAndPayload_forever_runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/modsecurity/playbooks/ansible_apply_only_ip_payload_modsecurity.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
                'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
                'secrule_anomaly_score': ip_address.get('anomaly_score'),
                'secrule_paranoia_level': ip_address.get('paranoia_level'),
                'secrule_payload': root_cause_value.replace('\"', '\\\"'),
                'secrule_id_ip': id_for_secrule_ip,
                'secrule_id_chain': id_for_secrule_chain,
                'secrule_ip': ip_source_value,
                'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{id_for_secrule_ip}-{id_for_secrule_chain}-{unique_id_onlyIPAndPayload_forever}',
                'modsec_container_name': ANSIBLE_MODSEC_CONAME
            },
            host_pattern='firewall',
            json_mode=True,
            quiet=True,
            ident=unique_id_onlyIPAndPayload_forever
        )
        if onlyIPAndPayload_forever_runner.rc != 0:
            for event in onlyIPAndPayload_forever_runner.events:
                if event.get('event') == 'runner_on_failed':
                    if event['event_data'].get('task') == 'fail':
                        response_elasticsearch.index(index='responser-modsecurity-errorlogs', document={
                            'responser_name': responser_name,
                            'message': event['stdout'],
                            'pattern': 'api/modsecurity/playbooks/ansible_apply_only_ip_payload_modsecurity.yaml'
                        })
                        break
            rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyIPAndPayload_forever}', ignore_errors=True)
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution_for_ip['_id'])
            response_elasticsearch.delete(index='responser-modsecurity-executions', id=modsecurity_execution_for_chain['_id'])
            return {
                'type': 'modsecurity_responser',
                'data': None,
                'reason': 'InternalServerError: "ansible_apply_only_ip_payload_modsecurity.yaml" can\'t run'
            }, 500
        time_now = datetime.now() + timedelta(hours=7)
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution_for_ip['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
            'relationship': id_for_secrule_chain,
            'real_id_relationship': modsecurity_execution_for_chain['_id']
        })
        response_elasticsearch.update(index='responser-modsecurity-executions', id=modsecurity_execution_for_chain['_id'], doc={
            'start': f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}',
            'relationship': id_for_secrule_ip,
            'real_id_relationship': modsecurity_execution_for_ip['_id']
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace('.', '')}artifacts/{unique_id_onlyIPAndPayload_forever}', ignore_errors=True)
    return {
        'type': 'modsecurity_responser',
        'data': {
            'regex': full_regex if full_regex is not None else regex_value.pattern if hasattr(regex_value, 'pattern') else regex_value,
            'ip': ip_source_value,
            'root': root_cause_value
        },
        'reason': 'Success'
    }

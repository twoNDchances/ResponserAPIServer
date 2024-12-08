from flask import Blueprint, request
from datetime import datetime
from hashlib import sha512
from ipaddress import ip_address as validate_ip_address
from json import dumps, loads
from pika import BlockingConnection, ConnectionParameters, PlainCredentials
import re
from requests import get
from .operations import modsecurity_operation_blueprint
from ..functions import get_value_from_json, generate_full_regex, replace_important_chars
from ..storage import (
    response_elasticsearch, 
    ES_MAX_RESULT,
    RABBITMQ_HOST,
    RABBITMQ_MANAGEMENT_PORT,
    RABBITMQ_OPERATION_PORT,
    RABBITMQ_USERNAME,
    RABBITMQ_PASSWORD,
    RABBITMQ_QUEUE_NAME
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
    is_ip_address: bool = ip_address.get('is_used')
    is_payload: bool = payload.get('is_used')
    based_payload = payload.get('based_payload')
    is_advanced: bool = advanced.get('is_enabled')
    getted_ip_address = False; getted_rule = False; getted_payload = False
    ip_source_value = None; regex_value = None
    full_regex = None; root_cause_value = None
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
        if based_payload is True:
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
    try:
        rabbitmq_respose = get(
            url=f'http://{RABBITMQ_HOST}:{RABBITMQ_MANAGEMENT_PORT}/api/healthchecks/node', 
            auth=(RABBITMQ_USERNAME, RABBITMQ_PASSWORD)
        )
        if rabbitmq_respose.status_code != 200:
            return {
                'type': 'modsecurity_responser',
                'data': None,
                'reason': f'InternalServerError: Check health RabbitMQ fail with status code {rabbitmq_respose.status_code}'
            }, 500
    except:
        return {
            'type': 'modsecurity_responser',
            'data': None,
            'reason': f'InternalServerError: Can\'t perform request GET for healthcheck RabbitMQ'
        }, 500
    connection = BlockingConnection(
        ConnectionParameters(
            host=RABBITMQ_HOST, 
            port=RABBITMQ_OPERATION_PORT, 
            credentials=PlainCredentials(
                username=RABBITMQ_USERNAME, 
                password=RABBITMQ_PASSWORD
            )
        )
    )
    channel = connection.channel()
    channel.queue_declare(queue=RABBITMQ_QUEUE_NAME, durable=True)
    secrule_processor = None
    if getted_ip_address is True and getted_rule is True and getted_payload is True:
        secrule_processor = {
            'responser_name': responser_name,
            'type': 'full',
            'details': {
                'ip': {
                    'source_ip': ip_source_value,
                    'anomaly_score': ip_address.get('anomaly_score'),
                    'paranoia_level': ip_address.get('paranoia_level')
                },
                'rule': replace_important_chars(string=full_regex),
                'payload': root_cause_value,
                'hashed_rule': sha512(string=replace_important_chars(string=full_regex).encode()).hexdigest(),
                'hashed_payload': sha512(string=root_cause_value.encode()).hexdigest()
            },
            'payload': request_body
        }
    if getted_ip_address is False and getted_rule is True and getted_payload is True:
        secrule_processor = {
            'responser_name': responser_name,
            'type': 'full',
            'details': {
                'ip': None,
                'rule': replace_important_chars(string=full_regex),
                'payload': root_cause_value,
                'hashed_rule': sha512(string=replace_important_chars(string=full_regex).encode()).hexdigest(),
                'hashed_payload': sha512(string=root_cause_value.encode()).hexdigest()
            },
            'payload': request_body
        }
    if getted_ip_address is False and getted_rule is False and getted_payload is True:
        secrule_processor = {
            'responser_name': responser_name,
            'type': 'onlyPayload',
            'details': {
                'ip': None,
                'rule': None,
                'payload': replace_important_chars(string=root_cause_value),
                'hashed_rule': None,
                'hashed_payload': sha512(string=root_cause_value.encode()).hexdigest()
            },
            'payload': request_body
        }
    if getted_ip_address is True and getted_rule is False and getted_payload is False:
        secrule_processor = {
            'responser_name': responser_name,
            'type': 'onlyIP',
            'details': {
                'ip': {
                    'source_ip': ip_source_value,
                    'anomaly_score': ip_address.get('anomaly_score'),
                    'paranoia_level': ip_address.get('paranoia_level')
                },
                'rule': None,
                'payload': None,
                'hashed_rule': None,
                'hashed_payload': None
            },
            'payload': request_body
        }
    if getted_ip_address is True and getted_rule is True and getted_payload is False:
        secrule_processor = {
            'responser_name': responser_name,
            'type': 'onlyIPAndRegex',
            'details': {
                'ip': {
                    'source_ip': ip_source_value,
                    'anomaly_score': ip_address.get('anomaly_score'),
                    'paranoia_level': ip_address.get('paranoia_level')
                },
                'rule': replace_important_chars(string=regex_value.pattern),
                'payload': None,
                'hashed_rule': sha512(string=replace_important_chars(string=regex_value.pattern).encode()).hexdigest(),
                'hashed_payload': None
            },
            'payload': request_body
        }
    if getted_ip_address is False and getted_rule is True and getted_payload is False:
        secrule_processor = {
            'responser_name': responser_name,
            'type': 'onlyRegex',
            'details': {
                'ip': None,
                'rule': replace_important_chars(string=regex_value.pattern),
                'payload': None,
                'hashed_rule': sha512(string=replace_important_chars(string=regex_value.pattern).encode()).hexdigest(),
                'hashed_payload': None
            },
            'payload': request_body
        }
    if getted_ip_address is True and getted_rule is False and getted_payload is True:
        secrule_processor = {
            'responser_name': responser_name,
            'type': 'onlyIPAndPayload',
            'details': {
                'ip': {
                    'source_ip': ip_source_value,
                    'anomaly_score': ip_address.get('anomaly_score'),
                    'paranoia_level': ip_address.get('paranoia_level')
                },
                'rule': None,
                'payload': replace_important_chars(string=root_cause_value),
                'hashed_rule': None,
                'hashed_payload': sha512(string=root_cause_value.encode()).hexdigest()
            },
            'payload': request_body
        }
    channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME, body=dumps(secrule_processor))
    connection.close()
    return {
        'type': 'modsecurity_responser',
        'data': {
            'regex': full_regex if full_regex is not None else regex_value.pattern if hasattr(regex_value, 'pattern') else regex_value,
            'ip': ip_source_value,
            'root': root_cause_value
        },
        'reason': 'Success'
    }

from json import dumps
from elasticsearch import Elasticsearch
from gather import (
    ES_HOST, 
    ES_USER, 
    ES_PASS, 
    ES_MAX_RESULT, 
    ANSIBLE_DATA_DIR, 
    ANSIBLE_INVENTORY, 
    ANSIBLE_FIREWALL_USERNAME, 
    ANSIBLE_FIREWALL_PASSWORD, 
    ANSIBLE_CRS_PATH_DIR, 
    ANSIBLE_MODSEC_CONAME,
    ANSIBLE_SWARM_USERNAME,
    ANSIBLE_SWARM_PASSWORD,
    RABBITMQ_HOST,
    RABBITMQ_MANAGEMENT_PORT,
    RABBITMQ_OPERATION_PORT,
    RABBITMQ_USERNAME,
    RABBITMQ_PASSWORD,
    RABBITMQ_QUEUE_NAME,
    RABBITMQ_SCALER_QNAME,
    PROMETHEUS_HOST,
    PROMETHEUS_PORT
)


response_elasticsearch = Elasticsearch(hosts=ES_HOST, basic_auth=(ES_USER, ES_PASS))

index_settings = {
    "settings": {
        "index": {
            "max_result_window": ES_MAX_RESULT
        }
    }
}

def reset_elasticsearch():
    if response_elasticsearch.ping() is False:
        return False
    
    if response_elasticsearch.indices.exists(index='responser-iptables'):
        response_elasticsearch.indices.delete(index='responser-iptables')
        response_elasticsearch.indices.create(index='responser-iptables', body=index_settings)
        response_elasticsearch.index(index='responser-iptables', document={
            'responser_name': 'default-iptables-responser',
            'responser_configuration': dumps({
                'is_enabled': True,
                'target_ip_field': 'ip_root_cause',
                'is_ruthless': False,
                'limit_duration_minutes': 1,
                'rate_limitation': {
                    'packet_nums': 3,
                    'duration_type': 'm',
                    'burst': 1
                },
                'block_duration_minutes': 1,
                'advanced': {
                    'is_enabled': False,
                    'threshold': 3,
                    'time_window_seconds': 30
                }
            })
        })
    
    if response_elasticsearch.indices.exists(index='responser-iptables-executions'):
        response_elasticsearch.indices.delete(index='responser-iptables-executions')
        response_elasticsearch.indices.create(index='responser-iptables-executions', body=index_settings)

    if response_elasticsearch.indices.exists(index='responser-iptables-timestamps'):
        response_elasticsearch.indices.delete(index='responser-iptables-timestamps')
        response_elasticsearch.indices.create(index='responser-iptables-timestamps', body=index_settings)

    if response_elasticsearch.indices.exists(index='responser-iptables-errorlogs'):
        response_elasticsearch.indices.delete(index='responser-iptables-errorlogs')
        response_elasticsearch.indices.create(index='responser-iptables-errorlogs', body=index_settings)
    
    if response_elasticsearch.indices.exists(index='responser-modsecurity'):
        response_elasticsearch.indices.delete(index='responser-modsecurity')
        response_elasticsearch.indices.create(index='responser-modsecurity', body=index_settings)
        response_elasticsearch.index(index='responser-modsecurity', document={
            'responser_name': 'default-modsecurity-responser',
            'responser_configuration': dumps({
                'is_enabled': True, 
                'ip_address': {
                    'is_used': False, 
                    'ip_source_field': 'ip_root_cause', 
                    'paranoia_level': 2, 
                    'anomaly_score': 4
                }, 
                'payload': {
                    'is_used': True, 
                    'based_payload': False, 
                    'regex_field': 'payload.message.by_rule', 
                    'root_cause_field': 'payload.message.field_value'
                }, 
                'advanced': {
                    'is_enabled': False, 
                    'threshold': 3, 
                    'time_window_seconds': 30
                }
            })
        })
    
    if response_elasticsearch.indices.exists(index='responser-modsecurity-executions'):
        response_elasticsearch.indices.delete(index='responser-modsecurity-executions')
        response_elasticsearch.indices.create(index='responser-modsecurity-executions', body=index_settings)

    if response_elasticsearch.indices.exists(index='responser-modsecurity-timestamps'):
        response_elasticsearch.indices.delete(index='responser-modsecurity-timestamps')
        response_elasticsearch.indices.create(index='responser-modsecurity-timestamps', body=index_settings)

    if response_elasticsearch.indices.exists(index='responser-modsecurity-errorlogs'):
        response_elasticsearch.indices.delete(index='responser-modsecurity-errorlogs')
        response_elasticsearch.indices.create(index='responser-modsecurity-errorlogs', body=index_settings)

    if response_elasticsearch.indices.exists(index='responser-swarm'):
        response_elasticsearch.indices.delete(index='responser-swarm')
        response_elasticsearch.indices.create(index='responser-swarm', body=index_settings)
        # response_elasticsearch.index(index='responser-swarm', document={
        #     'responser_name': 'analyzer',
        #     'responser_configuration': dumps({
        #         'is_enabled': True, 
        #         'scaling': {
        #             'up_nums': 5, 
        #             'down_nums': 1, 
        #         }
        #     }),
        #     'current_nums': 1
        # })
        response_elasticsearch.index(index='responser-swarm', document={
            'responser_name': 'analyzer_client',
            'responser_configuration': dumps({
                'is_enabled': True, 
                'scaling': {
                    'up_nums': 5, 
                    'down_nums': 1, 
                }
            }),
            'current_nums': 1
        })
        response_elasticsearch.index(index='responser-swarm', document={
            'responser_name': 'forwarder',
            'responser_configuration': dumps({
                'is_enabled': True, 
                'scaling': {
                    'up_nums': 5, 
                    'down_nums': 1, 
                }
            }),
            'current_nums': 1
        })
        response_elasticsearch.index(index='responser-swarm', document={
            'responser_name': 'packetbeat_nginx_gateway_services',
            'responser_configuration': dumps({
                'is_enabled': True, 
                'scaling': {
                    'up_nums': 3, 
                    'down_nums': 1, 
                }
            }),
            'current_nums': 1
        })
        # response_elasticsearch.index(index='responser-swarm', document={
        #     'responser_name': 'receiver',
        #     'responser_configuration': dumps({
        #         'is_enabled': True, 
        #         'scaling': {
        #             'up_nums': 7, 
        #             'down_nums': 1, 
        #         }
        #     }),
        #     'current_nums': 1
        # })
        response_elasticsearch.index(index='responser-swarm', document={
            'responser_name': 'registration_services',
            'responser_configuration': dumps({
                'is_enabled': True, 
                'scaling': {
                    'up_nums': 5, 
                    'down_nums': 1, 
                }
            }),
            'current_nums': 1
        })
        # response_elasticsearch.index(index='responser-swarm', document={
        #     'responser_name': 'responser',
        #     'responser_configuration': dumps({
        #         'is_enabled': True, 
        #         'scaling': {
        #             'up_nums': 5, 
        #             'down_nums': 1, 
        #         }
        #     }),
        #     'current_nums': 1
        # })
        response_elasticsearch.index(index='responser-swarm', document={
            'responser_name': 'responser_client',
            'responser_configuration': dumps({
                'is_enabled': True, 
                'scaling': {
                    'up_nums': 5, 
                    'down_nums': 1, 
                }
            }),
            'current_nums': 1
        })
        response_elasticsearch.index(index='responser-swarm', document={
            'responser_name': 'reviewer',
            'responser_configuration': dumps({
                'is_enabled': True, 
                'scaling': {
                    'up_nums': 15, 
                    'down_nums': 5, 
                }
            }),
            'current_nums': 5
        })
        # response_elasticsearch.index(index='responser-swarm', document={
        #     'responser_name': 'scaler',
        #     'responser_configuration': dumps({
        #         'is_enabled': True, 
        #         'scaling': {
        #             'up_nums': 5, 
        #             'down_nums': 1, 
        #         }
        #     }),
        #     'current_nums': 1
        # })
    
    if response_elasticsearch.indices.exists(index='responser-swarm-executions'):
        response_elasticsearch.indices.delete(index='responser-swarm-executions')
        response_elasticsearch.indices.create(index='responser-swarm-executions', body=index_settings)
        # response_elasticsearch.index(index='responser-swarm-executions', document={
        #     'responser_name': 'analyzer',
        #     'status': 'down',
        #     'at_time': None,
        #     'replicas': None,
        #     'last_action': None,
        #     'last_logs': None,
        # })
        response_elasticsearch.index(index='responser-swarm-executions', document={
            'responser_name': 'analyzer_client',
            'status': 'down',
            'at_time': None,
            'replicas': None,
            'last_action': None,
            'last_logs': None,
        })
        response_elasticsearch.index(index='responser-swarm-executions', document={
            'responser_name': 'forwarder',
            'status': 'down',
            'at_time': None,
            'replicas': None,
            'last_action': None,
            'last_logs': None,
        })
        response_elasticsearch.index(index='responser-swarm-executions', document={
            'responser_name': 'packetbeat_nginx_gateway_services',
            'status': 'down',
            'at_time': None,
            'replicas': None,
            'last_action': None,
            'last_logs': None,
        })
        # response_elasticsearch.index(index='responser-swarm-executions', document={
        #     'responser_name': 'receiver',
        #     'status': 'down',
        #     'at_time': None,
        #     'replicas': None,
        #     'last_action': None,
        #     'last_logs': None,
        # })
        response_elasticsearch.index(index='responser-swarm-executions', document={
            'responser_name': 'registration_services',
            'status': 'down',
            'at_time': None,
            'replicas': None,
            'last_action': None,
            'last_logs': None,
        })
        # response_elasticsearch.index(index='responser-swarm-executions', document={
        #     'responser_name': 'responser',
        #     'status': 'down',
        #     'at_time': None,
        #     'replicas': None,
        #     'last_action': None,
        #     'last_logs': None,
        # })
        response_elasticsearch.index(index='responser-swarm-executions', document={
            'responser_name': 'responser_client',
            'status': 'down',
            'at_time': None,
            'replicas': None,
            'last_action': None,
            'last_logs': None,
        })
        response_elasticsearch.index(index='responser-swarm-executions', document={
            'responser_name': 'reviewer',
            'status': 'down',
            'at_time': None,
            'replicas': None,
            'last_action': None,
            'last_logs': None,
        })
        # response_elasticsearch.index(index='responser-swarm-executions', document={
        #     'responser_name': 'scaler',
        #     'status': 'down',
        #     'at_time': None,
        #     'replicas': None,
        #     'last_action': None,
        #     'last_logs': None,
        # })

    if response_elasticsearch.indices.exists(index='responser-swarm-errorlogs'):
        response_elasticsearch.indices.delete(index='responser-swarm-errorlogs')
        response_elasticsearch.indices.create(index='responser-swarm-errorlogs', body=index_settings)

    return True
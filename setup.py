from json import dumps
from time import sleep
from api.storage import response_elasticsearch
from gather import ES_MAX_RESULT


def setup_elasticsearch():
    while True:
        try:
            if response_elasticsearch.ping() is True:
                break
            print('[Info] Perform connection testing fail, retry after 5 seconds')
            sleep(5)
        except:
            print('[Info] Perform connection testing fail, retry after 5 seconds')
            sleep(5)
            continue
    index_settings = {
        'settings': {
            'index': {
                'max_result_window': int(ES_MAX_RESULT)
            }
        }
    }
    print('[Info] Perform check "responser-iptables" index')
    if not response_elasticsearch.indices.exists(index='responser-iptables'):
        print('[Info] Creating "responser-iptables"...')
        response_elasticsearch.indices.create(index="responser-iptables", body=index_settings)
        print('[Info] Created "responser-iptables"')
        print('[Info] Perform create "responser-iptables" default responser')
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
        print('[Info] Creating done')
    print('[Info] Check done')

    print('[Info] Perform check "responser-iptables-executions" index')
    if not response_elasticsearch.indices.exists(index='responser-iptables-executions'):
        print('[Info] Creating "responser-iptables-executions"...')
        response_elasticsearch.indices.create(index="responser-iptables-executions", body=index_settings)
        print('[Info] Created "responser-iptables-executions"')
    print('[Info] Check done')

    print('[Info] Perform check "responser-iptables-timestamps" index')
    if not response_elasticsearch.indices.exists(index='responser-iptables-timestamps'):
        print('[Info] Creating "responser-iptables-timestamps"...')
        response_elasticsearch.indices.create(index="responser-iptables-timestamps", body=index_settings)
        print('[Info] Created "responser-iptables-timestamps"')
    print('[Info] Check done')
    
    print('[Info] Perform check "responser-iptables-errorlogs" index')
    if not response_elasticsearch.indices.exists(index='responser-iptables-errorlogs'):
        print('[Info] Creating "responser-iptables-errorlogs"...')
        response_elasticsearch.indices.create(index="responser-iptables-errorlogs", body=index_settings)
        print('[Info] Created "responser-iptables-errorlogs"')
    print('[Info] Check done')

    print('[Info] Perform check "responser-modsecurity" index')
    if not response_elasticsearch.indices.exists(index='responser-modsecurity'):
        print('[Info] Creating "responser-modsecurity"...')
        response_elasticsearch.indices.create(index="responser-modsecurity", body=index_settings)
        print('[Info] Created "responser-modsecurity"')
        print('[Info] Perform create "responser-modsecurity" default responser')
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
        print('[Info] Creating done')
    print('[Info] Check done')

    print('[Info] Perform check "responser-modsecurity-executions" index')
    if not response_elasticsearch.indices.exists(index='responser-modsecurity-executions'):
        print('[Info] Creating "responser-modsecurity-executions"...')
        response_elasticsearch.indices.create(index="responser-modsecurity-executions", body=index_settings)
        print('[Info] Created "responser-modsecurity-executions"')
    print('[Info] Check done')

    print('[Info] Perform check "responser-modsecurity-timestamps" index')
    if not response_elasticsearch.indices.exists(index='responser-modsecurity-timestamps'):
        print('[Info] Creating "responser-modsecurity-timestamps"...')
        response_elasticsearch.indices.create(index="responser-modsecurity-timestamps", body=index_settings)
        print('[Info] Created "responser-modsecurity-timestamps"')
    print('[Info] Check done')
    
    print('[Info] Perform check "responser-modsecurity-errorlogs" index')
    if not response_elasticsearch.indices.exists(index='responser-modsecurity-errorlogs'):
        print('[Info] Creating "responser-modsecurity-errorlogs"...')
        response_elasticsearch.indices.create(index="responser-modsecurity-errorlogs", body=index_settings)
        print('[Info] Created "responser-modsecurity-errorlogs"')
    print('[Info] Check done')

    print('[Info] Perform check "responser-swarm" index')
    if not response_elasticsearch.indices.exists(index='responser-swarm'):
        print('[Info] Creating "responser-swarm"...')
        response_elasticsearch.indices.create(index="responser-swarm", body=index_settings)
        print('[Info] Created "responser-swarm"')
        print('[Info] Perform create "responser-swarm" default responser')
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
        # response_elasticsearch.index(index='responser-swarm', document={
        #     'responser_name': 'forwarder',
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
        print('[Info] Creating done')
    print('[Info] Check done')

    print('[Info] Perform check "responser-swarm-executions" index')
    if not response_elasticsearch.indices.exists(index='responser-swarm-executions'):
        print('[Info] Creating "responser-swarm-executions"...')
        response_elasticsearch.indices.create(index="responser-swarm-executions", body=index_settings)
        print('[Info] Created "responser-swarm-executions"')
        print('[Info] Perform create "responser-swarm" default responser')
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
        # response_elasticsearch.index(index='responser-swarm-executions', document={
        #     'responser_name': 'forwarder',
        #     'status': 'down',
        #     'at_time': None,
        #     'replicas': None,
        #     'last_action': None,
        #     'last_logs': None,
        # })
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
        print('[Info] Creating done')
    print('[Info] Check done')

    print('[Info] Perform check "responser-swarm-errorlogs" index')
    if not response_elasticsearch.indices.exists(index='responser-swarm-errorlogs'):
        print('[Info] Creating "responser-swarm-errorlogs"...')
        response_elasticsearch.indices.create(index="responser-swarm-errorlogs", body=index_settings)
        print('[Info] Created "responser-swarm-errorlogs"')
    print('[Info] Check done')

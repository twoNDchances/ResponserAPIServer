from api.storage import response_elasticsearch
from gather import ES_MAX_RESULT


def setup_elasticsearch():
    while True:
        if response_elasticsearch.ping() is True:
            break
    index_settings = {
        "settings": {
            "index": {
                "max_result_window": int(ES_MAX_RESULT)
            }
        }
    }
    print('[Info] Perform check "responser-iptables" index')
    if not response_elasticsearch.indices.exists(index='responser-iptables'):
        print('[Info] Creating "responser-iptables"...')
        response_elasticsearch.indices.create(index="responser-iptables", body=index_settings)
        print('[Info] Created "responser-iptables"')
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

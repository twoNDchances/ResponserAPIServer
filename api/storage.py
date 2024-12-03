from elasticsearch import Elasticsearch
from gather import ES_HOST, ES_USER, ES_PASS, ES_MAX_RESULT, ANSIBLE_DATA_DIR, ANSIBLE_INVENTORY, ANSIBLE_FIREWALL_USERNAME, ANSIBLE_FIREWALL_PASSWORD, ANSIBLE_CRS_PATH_DIR, ANSIBLE_MODSEC_CONAME


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
    
    if response_elasticsearch.indices.exists(index='responser-modsecurity-executions'):
        response_elasticsearch.indices.delete(index='responser-modsecurity-executions')
        response_elasticsearch.indices.create(index='responser-modsecurity-executions', body=index_settings)

    if response_elasticsearch.indices.exists(index='responser-modsecurity-timestamps'):
        response_elasticsearch.indices.delete(index='responser-modsecurity-timestamps')
        response_elasticsearch.indices.create(index='responser-modsecurity-timestamps', body=index_settings)

    if response_elasticsearch.indices.exists(index='responser-modsecurity-errorlogs'):
        response_elasticsearch.indices.delete(index='responser-modsecurity-errorlogs')
        response_elasticsearch.indices.create(index='responser-modsecurity-errorlogs', body=index_settings)

    return True
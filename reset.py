from setup import response_elasticsearch

if response_elasticsearch.indices.exists(index='responser-iptables'):
    response_elasticsearch.indices.delete(index='responser-iptables')
if response_elasticsearch.indices.exists(index='responser-iptables-executions'):
    response_elasticsearch.indices.delete(index='responser-iptables-executions')
if response_elasticsearch.indices.exists(index='responser-iptables-timestamps'):
    response_elasticsearch.indices.delete(index='responser-iptables-timestamps')
if response_elasticsearch.indices.exists(index='responser-iptables-errorlogs'):
    response_elasticsearch.indices.delete(index='responser-iptables-errorlogs')
if response_elasticsearch.indices.exists(index='responser-modsecurity'):
    response_elasticsearch.indices.delete(index='responser-modsecurity')
if response_elasticsearch.indices.exists(index='responser-modsecurity-executions'):
    response_elasticsearch.indices.delete(index='responser-modsecurity-executions')
if response_elasticsearch.indices.exists(index='responser-modsecurity-timestamps'):
    response_elasticsearch.indices.delete(index='responser-modsecurity-timestamps')
if response_elasticsearch.indices.exists(index='responser-modsecurity-errorlogs'):
    response_elasticsearch.indices.delete(index='responser-modsecurity-errorlogs')
if response_elasticsearch.indices.exists(index='responser-swarm'):
    response_elasticsearch.indices.delete(index='responser-swarm')
if response_elasticsearch.indices.exists(index='responser-swarm-executions'):
    response_elasticsearch.indices.delete(index='responser-swarm-executions')
if response_elasticsearch.indices.exists(index='responser-swarm-errorlogs'):
    response_elasticsearch.indices.delete(index='responser-swarm-errorlogs')

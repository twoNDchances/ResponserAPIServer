from flask import Blueprint, request
from datetime import datetime
from json import loads, dumps
from pika import BlockingConnection, ConnectionParameters, PlainCredentials
from prometheus_api_client import PrometheusConnect
from .operations import swarm_operation_blueprint
from ..storage import (
    response_elasticsearch,
    ES_MAX_RESULT,
    RABBITMQ_HOST,
    RABBITMQ_MANAGEMENT_PORT,
    RABBITMQ_OPERATION_PORT,
    RABBITMQ_USERNAME,
    RABBITMQ_PASSWORD,
    RABBITMQ_SCALER_QNAME,
    PROMETHEUS_HOST,
    PROMETHEUS_PORT
)


swarm_main_blueprint = Blueprint(name='swarm_main_blueprint', import_name=__name__)

swarm_main_blueprint.register_blueprint(blueprint=swarm_operation_blueprint, url_prefix='/swarm')

swarm_responser_blueprint = Blueprint(name='swarm_responser_blueprint', import_name=__name__)

@swarm_responser_blueprint.route(rule='/swarm', methods=['POST', 'GET'])
def swarm_responser_endpoint():
    if response_elasticsearch.ping() is False:
        return {
            'type': 'swarm_responser',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
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
            'type': 'swarm_responser',
            'data': None,
            'reason': 'BadRequest: Body must be JSON'
        }, 400
    request_body: dict = request.get_json()
    alerts: list[dict] = request_body.get('alerts')
    checklist: list[dict] = []
    for alert in alerts:
        labels: dict = alert.get('labels')
        annotations: dict = alert.get('annotations')
        if not all([labels, annotations]):
            continue
        stack_name = labels.get('container_label_com_docker_stack_namespace')
        service_name = labels.get('container_label_com_docker_swarm_service_name')
        metric = annotations.get('metric')
        object = annotations.get('object')
        type = annotations.get('type')
        if not all([stack_name, service_name, metric, object, type]):
            continue
        real_service_name = service_name.replace(f'{stack_name}_', '')
        metric = round(float(metric), 2)
        if checklist.__len__() == 0 or [container for container in checklist if container.get('real_name') == real_service_name].__len__() == 0:
            checklist.append({
                'real_name': real_service_name,
                'service_name': service_name,
                'ram': {
                    'metric': metric if object == 'RAM' else None,
                    'type': type if object == 'RAM' else type if object == 'RAM' else None
                },
                'cpu': {
                    'metric': metric if object == 'CPU' else None,
                    'type': type if object == 'CPU' else type if object == 'CPU' else None
                }
            })
        for container in checklist:
            if container.get('real_name') == real_service_name:
                ram: dict = container.get('ram')
                if ram.get('metric') is None and object == 'RAM':
                    ram['metric'] = metric
                    ram['type'] = type
                cpu: dict = container.get('cpu')
                if cpu.get('metric') is None and object == 'CPU':
                    cpu['metric'] = metric
                    cpu['type'] = type
    performlist = []
    for chlist in checklist:
        ram: dict = chlist.get('ram')
        cpu: dict = chlist.get('cpu')
        final_action = None
        if ram.get('type') == 'scaleUp' and cpu.get('type') == 'scaleUp':
            final_action = 'up'
        if ram.get('type') == 'scaleUp' and cpu.get('type') == 'scaleDown':
            final_action = 'up'
        if ram.get('type') == 'scaleDown' and cpu.get('type') == 'scaleUp':
            final_action = 'up'
        if ram.get('type') == 'scaleDown' and cpu.get('type') == 'scaleDown':
            final_action = 'down'
        if ram.get('type') == None and cpu.get('type') == 'scaleDown':
            final_action = 'down'
        if ram.get('type') == None and cpu.get('type') == 'scaleUp':
            final_action = 'up'
        if ram.get('type') == 'scaleDown' and cpu.get('type') == None:
            final_action = 'down'
        if ram.get('type') == 'scaleUp' and cpu.get('type') == None:
            final_action = 'up'
        performlist.append({
            'real_name': chlist.get('real_name'),
            'service_name': chlist.get('service_name'),
            'ram': ram.get('metric'),
            'cpu': cpu.get('metric'),
            'final_action': final_action
        })
    prometheus = PrometheusConnect(url=f'{PROMETHEUS_HOST}:{PROMETHEUS_PORT}', disable_ssl=True)
    ram_query = 'sum(node_memory_MemAvailable_bytes)'
    ram_result = prometheus.custom_query(query=ram_query)
    ram_free_mb = float(ram_result[0]['value'][1])
    cpu_idle_query = 'sum(rate(node_cpu_seconds_total{mode="idle"}[1m]))'
    cpu_idle_result = prometheus.custom_query(query=cpu_idle_query)
    total_idle_cores = float(cpu_idle_result[0]['value'][1])
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
    channel.queue_declare(queue=RABBITMQ_SCALER_QNAME, durable=True)
    swarm = response_elasticsearch.search(index='responser-swarm', query={'match_all': {}}, size=ES_MAX_RESULT).raw['hits']['hits']
    up_nums = 0
    for pflist in performlist:
        if pflist.get('real_name') in [container['_source']['responser_name'] for container in swarm]:
            container_configuration = [
                container for container in swarm
                if container['_source']['responser_name'] == pflist.get('real_name')
            ][0]
            responser_configuration: dict = loads(container_configuration['_source']['responser_configuration'])
            if responser_configuration.get('is_enabled') is False:
                response_elasticsearch.index(index='responser-swarm-errorlogs', document={
                    'responser_name': pflist.get('real_name'),
                    'message': f'Responser of "{pflist.get("real_name")}" is disabled',
                    'pattern': f'["is_enabled" = {responser_configuration.get("is_enabled")}]'
                })
                continue
            current_nums = container_configuration['_source']['current_nums']
            scaling: dict = responser_configuration.get('scaling')
            swarm_execution = response_elasticsearch.search(index='responser-swarm-executions', query={
                'term': {
                    'responser_name.keyword': pflist.get('real_name')
                }
            }).raw['hits']['hits'][0]
            time_now = int(datetime.now().timestamp())
            if pflist.get('final_action') == 'down':
                if swarm_execution['_source']['status'] == 'up':
                    if (swarm_execution['_source']['at_time'] + 30) <= time_now:
                        scaling_execution = {
                            'service_name': pflist.get('service_name'),
                            'real_name': pflist.get('real_name'),
                            'execution_id': swarm_execution['_id'],
                            'swarm_id': container_configuration['_id'],
                            'scaling': 'down',
                            'replicas': scaling.get('down_nums'),
                            'auto_down_after_minutes': None
                        }
                        print(scaling_execution)
                        channel.basic_publish(exchange='', routing_key=RABBITMQ_SCALER_QNAME, body=dumps(scaling_execution))
                continue
            if swarm_execution['_source']['status'] == 'down':
                if swarm_execution['_source']['at_time'] is not None and (swarm_execution['_source']['at_time'] + 30) > time_now:
                    continue
            container_ram_limit_query = prometheus.custom_query(
                query=f'container_spec_memory_limit_bytes{{container_label_com_docker_swarm_service_name="{pflist.get('service_name')}"}}'
            )
            container_cpu_limit_query = prometheus.custom_query(
                query=f'container_spec_cpu_quota{{container_label_com_docker_swarm_service_name="{pflist.get('service_name')}"}}'
            )
            if container_ram_limit_query == 0 or not container_cpu_limit_query:
                response_elasticsearch.index(index='responser-swarm-errorlogs', document={
                    'responser_name': pflist.get('real_name'),
                    'message': f'"{pflist.get("real_name")}" no limit set for RAM and CPU',
                    'pattern': f'["ram_limit" = {container_ram_limit_query}, "cpu_limit" = {container_cpu_limit_query}]'
                })
                continue
            container_ram_limit_result = float(container_ram_limit_query[0]['value'][1])
            container_cpu_limit_result = float(container_cpu_limit_query[0]['value'][1]) / 100000
            up_nums = scaling.get('up_nums') - current_nums
            container_ram_usage = up_nums * container_ram_limit_result
            container_cpu_usage = up_nums * container_cpu_limit_result
            container_ram_remaining = ram_free_mb - container_ram_usage
            container_cpu_remaining = total_idle_cores - container_cpu_usage
            insufficient_resources = False
            if container_ram_remaining <= 0 or container_cpu_remaining <= 0:
                insufficient_resources = True
                try_up_nums = [i for i in range(1, scaling.get('up_nums'))]
                try_up_nums.reverse()
                got_num = False
                for num in try_up_nums:
                    container_ram_usage = num * container_ram_limit_result
                    container_cpu_usage = num * container_cpu_limit_result
                    container_ram_remaining = ram_free_mb - container_ram_usage
                    container_cpu_remaining = total_idle_cores - container_cpu_usage
                    if container_ram_remaining > 0 and container_cpu_remaining > 0:
                        got_num = True
                        up_nums = num + current_nums
                        break
                if got_num is False:
                    response_elasticsearch.index(index='responser-swarm-errorlogs', document={
                        'responser_name': pflist.get('real_name'),
                        'message': f'Responser of "{pflist.get("real_name")}" can\'t scale up',
                        'pattern': 'Server resources insufficient'
                    })
                    continue
            scaling_execution = {
                'service_name': pflist.get('service_name'),
                'real_name': pflist.get('real_name'),
                'execution_id': swarm_execution['_id'],
                'swarm_id': container_configuration['_id'],
                'scaling': 'up',
                'replicas': scaling.get('up_nums') if insufficient_resources is False else up_nums
            }
            channel.basic_publish(exchange='', routing_key=RABBITMQ_SCALER_QNAME, body=dumps(scaling_execution))
            connection.close()
    return {
        'type': 'swarm',
        'data': None,
        'reason': 'Success'
    }, 200


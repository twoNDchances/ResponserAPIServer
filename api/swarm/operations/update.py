from flask import request
from flask_restful import Resource
from ansible_runner import run
from json import loads, dumps
from prometheus_api_client import PrometheusConnect
from requests import get
from shutil import rmtree
from uuid import uuid4
from ...storage import (
    response_elasticsearch,
    ES_MAX_RESULT,
    ANSIBLE_DATA_DIR,
    ANSIBLE_INVENTORY,
    ANSIBLE_SWARM_USERNAME,
    ANSIBLE_SWARM_PASSWORD,
    RABBITMQ_HOST,
    RABBITMQ_MANAGEMENT_PORT,
    RABBITMQ_USERNAME,
    RABBITMQ_PASSWORD,
    PROMETHEUS_HOST,
    PROMETHEUS_PORT
)


class SwarmModifications(Resource):
    def put(self, id: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            loads(request.data)
        except:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        try:
            swarm = response_elasticsearch.get(index='responser-swarm', id=id).raw
        except:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotFound: Responser Name not found'
            }, 404
        request_body = dict(request.get_json())
        responser_name = request_body.get('responserName')
        responser_configuration = request_body.get('responserConfiguration')
        if not all([responser_name, responser_configuration]):
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields ["responser_name", "responser_configuration"]'
            }, 400
        if not isinstance(responser_name, str) or not isinstance(responser_configuration, dict):
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["responser_name" => (string), "responser_configuration" => (json)]'
            }, 406
        is_enabled = responser_configuration.get('is_enabled')
        scaling = responser_configuration.get('scaling')
        if is_enabled is None or not all([scaling]):
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "responser_configuration" ["is_enabled", "scaling"]'
            }, 400
        if not isinstance(is_enabled, bool) or not isinstance(scaling, dict):
            return {
                'type': 'modsecurity',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["is_enabled" => (boolean), "scaling" => (json)'
            }, 406
        up_nums = scaling.get('up_nums')
        down_nums = scaling.get('down_nums')
        if not all([up_nums, down_nums]):
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "scaling" ["up_nums", "down_nums", "current_nums"]'
            }, 400
        if not isinstance(up_nums, int) or not isinstance(down_nums, int):
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["up_nums" => (integer), "down_nums" => (integer), "current_nums" => (integer)]'
            }, 406
        if up_nums == 0 or down_nums == 0:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotAcceptable: All scaling configuration number must greater than 0'
            }, 406
        if down_nums >= up_nums:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotAcceptable: "down_nums" must be less than "up_nums"'
            }, 406
        swarm_execution = response_elasticsearch.search(index='responser-swarm-executions', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw['hits']['hits'][0]
        swarm_responser_configuration: dict = loads(swarm['_source']['responser_configuration'])
        swarm_scaling: dict = swarm_responser_configuration.get('scaling')
        swarm_up_nums = swarm_scaling.get('up_nums')
        swarm_down_nums = swarm_scaling.get('down_nums')
        swarm_current_nums = swarm['_source']['current_nums']
        if swarm_execution['_source']['status'] == 'up':
            if swarm_up_nums != up_nums:
                return {
                    'type': 'swarm',
                    'data': None,
                    'reason': 'NotAcceptable: Status of this server is Up, so can\'t update "up_nums" parameter'
                }, 406
            if down_nums >= swarm_current_nums:
                return {
                    'type': 'swarm',
                    'data': None,
                    'reason': 'NotAcceptable: "down_nums" must less than Current Replicas'
                }, 406
        if swarm_execution['_source']['status'] == 'down':
            if swarm_down_nums != down_nums:
                return {
                    'type': 'swarm',
                    'data': None,
                    'reason': 'NotAcceptable: Status of this server is Down, so can\'t update "down_nums" parameter'
                }, 406
            if up_nums <= swarm_current_nums:
                return{
                    'type': 'swarm',
                    'data': None,
                    'reason': 'NotAcceptable: "up_nums" must greater than Current Replicas'
                }, 406
        try:
            rabbitmq_response = get(
                url=f'http://{RABBITMQ_HOST}:{RABBITMQ_MANAGEMENT_PORT}/api/healthchecks/node', 
                auth=(
                    RABBITMQ_USERNAME, 
                    RABBITMQ_PASSWORD
                )
            )
            if rabbitmq_response.status_code != 200:
                return {
                    'type': 'swarm',
                    'data': None,
                    'reason': f'InternalServerError: RabbitMQ healthcheck fail with HTTP status code {rabbitmq_response.status_code}'
                }, 500
        except:
            return {
                'type': 'swarm',
                'data': None,
                'reason': f'InternalServerError: Can\'t perform GET request to RabbitMQ for connection testing'
            }, 500
        try:
            prometheus_response = PrometheusConnect(url=f'{PROMETHEUS_HOST}:{PROMETHEUS_PORT}', disable_ssl=True)
            if prometheus_response.check_prometheus_connection() is False:
                return {
                    'type': 'swarm',
                    'data': None,
                    'reason': f'InternalServerError: Prometheus check connection fail'
                }, 500
        except:
            return {
                'type': 'swarm',
                'data': None,
                'reason': f'InternalServerError: Can\'t perform check Prometheus for connection testing'
            }, 500
        unique_id = uuid4()
        runner = run(
            private_data_dir=ANSIBLE_DATA_DIR,
            playbook='../api/swarm/playbooks/ansible_check_update_swarm.yaml',
            inventory=ANSIBLE_INVENTORY,
            extravars={
                'username_swarm_node': ANSIBLE_SWARM_USERNAME,
                'password_swarm_node': ANSIBLE_SWARM_PASSWORD,
                'service_name': responser_name,
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
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'InternalServerError' if error_message is None else f'InternalServerError: {error_message}'
            }, 500
        response_elasticsearch.update(index='responser-swarm', id=swarm['_id'], doc={
            'responser_name': responser_name,
            'responser_configuration': dumps({
                'is_enabled': is_enabled,
                'scaling': {
                    'up_nums': up_nums,
                    'down_nums': down_nums
                }
            })
        })
        rmtree(path=f'{ANSIBLE_DATA_DIR.replace(".", "")}artifacts/{unique_id}', ignore_errors=True)
        return {
            'type': 'swarm',
            'data': {
                'id': swarm['_id'],
                'responser_name': responser_name,
                'is_enabled': is_enabled,
                'up_nums': up_nums,
                'down_nums': down_nums
            },
            'reason': 'Success'
        }

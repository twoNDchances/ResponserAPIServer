from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class SwarmLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        swarm = response_elasticsearch.search(index='responser-swarm', query={'match_all': {}}, size=ES_MAX_RESULT).raw
        if swarm['hits']['hits'].__len__() == 0:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'swarm',
            'data': [{
                'id': modsec['_id'],
                'responser_name': modsec['_source']['responser_name'],
                'is_enabled': loads(modsec['_source']['responser_configuration']).get('is_enabled'),
                'up_nums': loads(modsec['_source']['responser_configuration']).get('scaling').get('up_nums'),
                'down_nums': loads(modsec['_source']['responser_configuration']).get('scaling').get('down_nums'),
            } for modsec in swarm['hits']['hits']],
            'reason': 'Success'
        }


class SwarmExecutionLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        swarm_executions = response_elasticsearch.search(index='responser-swarm-executions', query={'match_all': {}}, size=ES_MAX_RESULT).raw['hits']['hits']
        if swarm_executions.__len__() == 0:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'swarm',
            'data': [{
                'id': swarm_execution['_id'],
                'responser_name': swarm_execution['_source']['responser_name'],
                'status': swarm_execution['_source']['status'],
                'replicas': swarm_execution['_source']['replicas'],
                'last_action': swarm_execution['_source']['last_action'],
            } for swarm_execution in swarm_executions],
            'reason': 'Success'
        }


class SwarmErrorLogsLists(Resource):
    def get(self, responser_name: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not responser_name:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'BadRequest: Responser Name is required'
            }, 400
        error_logs = response_elasticsearch.search(index='responser-swarm-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if error_logs['hits']['hits'].__len__() == 0:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'swarm',
            'data': [{
                'message': error_log['_source']['message'],
                'pattern': error_log['_source']['pattern']
            } for error_log in error_logs['hits']['hits']],
            'reason': 'Success'
        }
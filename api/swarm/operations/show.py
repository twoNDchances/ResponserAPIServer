from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class SwarmManifests(Resource):
    def get(self, id: str):
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
            swarm = response_elasticsearch.get(index='responser-swarm', id=id).raw
        except:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'swarm',
            'data': {
                'id': swarm['_id'],
                'responser_name': swarm['_source']['responser_name'],
                'responser_configuration': swarm['_source']['responser_configuration'],
                'current_nums': swarm['_source']['current_nums']
            },
            'reason': 'Success'
        }


class SwarmExecutionLastLogs(Resource):
    def get(self, id: str):
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
            swarm = response_elasticsearch.get(index='responser-swarm-executions', id=id).raw
        except:
            return {
                'type': 'swarm',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'swarm',
            'data': {
                'last_logs': swarm['_source']['last_logs']
            },
            'reason': 'Success'
        }
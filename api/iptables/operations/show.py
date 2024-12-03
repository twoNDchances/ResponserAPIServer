from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class IPTablesManifests(Resource):
    def get(self, id: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            iptable = response_elasticsearch.get(index='responser-iptables', id=id).raw
        except:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'iptables',
            'data': {
                'id': iptable['_id'],
                'responser_name': iptable['_source']['responser_name'],
                'responser_configuration': iptable['_source']['responser_configuration']
            },
            'reason': 'Success'
        }


class IPTablesPayloadManifests(Resource):
    def get(self, id: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            payload = response_elasticsearch.get(index='responser-iptables-executions', id=id).raw
        except:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'iptables',
            'data': payload['_source']['payload'],
            'reason': 'Success'
        }

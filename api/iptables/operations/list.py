from flask_restful import Resource
from datetime import datetime, timedelta
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class IPTablesLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        iptables = response_elasticsearch.search(index='responser-iptables', query={'match_all': {}}, size=ES_MAX_RESULT).raw
        if iptables['hits']['hits'].__len__() == 0:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'iptables',
            'data': [{
                'id': iptable['_id'],
                'responser_name': iptable['_source']['responser_name'],
                'is_enabled': loads(iptable['_source']['responser_configuration']).get('is_enabled'),
                'target_ip_field': loads(iptable['_source']['responser_configuration']).get('target_ip_field'),
                'is_ruthless': loads(iptable['_source']['responser_configuration']).get('is_ruthless'),
                'limit_duration_minutes': loads(iptable['_source']['responser_configuration']).get('limit_duration_minutes'),
                'block_duration_minutes': loads(iptable['_source']['responser_configuration']).get('block_duration_minutes'),
                'advanced': loads(iptable['_source']['responser_configuration']).get('advanced').get('is_enabled'),
            } for iptable in iptables['hits']['hits']],
            'reason': 'Success'
        }


class IPTablesExecutionLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        iptables_executions = response_elasticsearch.search(index='responser-iptables-executions', query={'match_all': {}}, size=ES_MAX_RESULT).raw
        if iptables_executions['hits']['hits'].__len__() == 0:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'iptables',
            'data': [{
                'id': iptables_execution['_id'],
                'responser_name': iptables_execution['_source']['responser_name'],
                'target_ip_field': iptables_execution['_source']['target_ip_field'],
                'state': iptables_execution['_source']['state'],
                'start': iptables_execution['_source']['start'],
                'finish': iptables_execution['_source']['finish'],
                'expired': False if iptables_execution['_source']['end_at'] is None else True if (datetime.now() + timedelta(hours=7)).timestamp() >= iptables_execution['_source']['end_at'] else False
            } for iptables_execution in iptables_executions['hits']['hits']],
            'reason': 'Success'
        }


class IPTablesErrorlogLists(Resource):
    def get(self, responser_name: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not responser_name:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Responser Name is required'
            }, 400
        error_logs = response_elasticsearch.search(index='responser-iptables-errorlogs', query={
            'term': {
                'responser_name.keyword': responser_name
            }
        }, size=ES_MAX_RESULT).raw
        if error_logs['hits']['hits'].__len__() == 0:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'iptables',
            'data': [{
                'message': error_log['_source']['message'],
                'pattern': error_log['_source']['pattern']
            } for error_log in error_logs['hits']['hits']],
            'reason': 'NotFound'
        }

from flask import request
from flask_restful import Resource
from json import dumps, loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class IPTablesModifications(Resource):
    def put(self, id: str):
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
        try:
            loads(request.data)
        except:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        responser_name = request_body.get('responserName')
        responser_configuration = request_body.get('responserConfiguration')
        if not all([responser_name, responser_configuration]):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields ["responser_name", "responser_configuration"]'
            }, 400
        if not isinstance(responser_name, str) or not isinstance(responser_configuration, dict):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["responser_name" => (string), "responser_configuration" => (json)]'
            }, 406
        is_enabled_configuration = responser_configuration.get('is_enabled')
        is_ruthless = responser_configuration.get('is_ruthless')
        target_ip_field = responser_configuration.get('target_ip_field')
        limit_duration_minutes = responser_configuration.get('limit_duration_minutes')
        block_duration_minutes = responser_configuration.get('block_duration_minutes')
        rate_limitation = responser_configuration.get('rate_limitation')
        advanced = responser_configuration.get('advanced')
        if is_enabled_configuration is None or is_ruthless is None or limit_duration_minutes is None or block_duration_minutes is None:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "responser_configuration" ["is_enabled", "is_ruthless", "target_ip_field", "limit_duration_minutes", "block_duration_minutes", "rate_limitation", "advanced"]'
            }, 400
        if not all([target_ip_field, rate_limitation, advanced]):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "responser_configuration" ["is_enabled", "target_ip_field", "limit_duration_minutes", "block_duration_minutes", "rate_limitation", "advanced"]'
            }, 400
        if not isinstance(is_enabled_configuration, bool) or not isinstance(is_ruthless, bool) or not isinstance(target_ip_field, str) or not isinstance(limit_duration_minutes, int) or not isinstance(block_duration_minutes, int) or not isinstance(rate_limitation, dict) or not isinstance(advanced, dict):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["is_enabled" => (boolean), "is_ruthless" => (boolean), "target_ip_field" => (string), "limit_duration_minutes" => (integer), "block_duration_minutes" => (integer), "rate_limitation" => (json), "advanced" => (json)]'
            }, 406
        if not (limit_duration_minutes > 0) or not (block_duration_minutes > 0):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotAcceptable: "limit_duration_minutes", "block_duration_minutes" must be greater than 0'
            }, 406
        packet_nums = rate_limitation.get('packet_nums')
        duration_type = rate_limitation.get('duration_type')
        burst = rate_limitation.get('burst')
        if packet_nums is None or burst is None:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "rate_limitation" ["packet_nums", "duration_type", "burst"]'
            }, 400
        if not duration_type:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "rate_limitation" ["packet_nums", "duration_type", "burst"]'
            }, 400
        if not isinstance(packet_nums, int) or not isinstance(duration_type, str) or not isinstance(burst, int):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["packet_nums" => (integer), "duration_type" => (string), "burst" => (integer)]'
            }, 406
        if not (packet_nums > 0) or not (burst > 0):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotAcceptable: "packet_nums", "burst" must be greater than 0'
            }, 406
        if duration_type not in ['s', 'm', 'h', 'd']:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotAcceptable: "duration_type" must be in ["s" => (second), "m" => (minute), "h" => (hour), "d" => (day)]'
            }, 406
        is_enabled = advanced.get('is_enabled')
        threshold = advanced.get('threshold')
        time_window_seconds = advanced.get('time_window_seconds')
        if is_enabled is None:
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "advanced" ["is_enabled", "threshold", "time_window_seconds"]'
            }, 400
        if not all([threshold, time_window_seconds]):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'BadRequest: Missing requirement fields from "advanced" ["is_enabled", "threshold", "time_window_seconds"]'
            }, 400
        if not isinstance(is_enabled, bool) or not isinstance(threshold, int) or not isinstance(time_window_seconds, int):
            return {
                'type': 'iptables',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["is_enabled" => (boolean), "threshold" => (integer), "time_window_seconds" => (integer)]'
            }, 406
        if responser_name != iptable['_source']['responser_name']:
            if response_elasticsearch.search(index='responser-iptables', query={
                'term': {
                    'responser_name.keyword': responser_name
                }
            }, size=ES_MAX_RESULT).raw['hits']['hits'].__len__() > 0:
                return {
                    'type': 'iptables',
                    'data': None,
                    'reason': 'NotAcceptable: Responser Name is exist'
                }, 406
            iptables_executions = response_elasticsearch.search(index='responser-iptables-executions', query={
                'term': {
                    'responser_name.keyword': iptable['_source']['responser_name']
                }
            }).raw
            if iptables_executions['hits']['hits'].__len__() > 0:
                for iptables_execution in iptables_executions['hits']['hits']:
                    response_elasticsearch.update(index='responser-iptables-executions', id=iptables_execution['_id'], doc={
                        'responser_name': responser_name
                    })
            iptables_timestamps = response_elasticsearch.search(index='responser-iptables-timestamps', query={
                'term': {
                    'responser_name.keyword': iptable['_source']['responser_name']
                }
            }).raw
            if iptables_timestamps['hits']['hits'].__len__() > 0:
                for iptables_timestamp in iptables_timestamps['hits']['hits']:
                    response_elasticsearch.update(index='responser-iptables-timestamps', id=iptables_timestamp['_id'], doc={
                        'responser_name': responser_name
                    })
            iptables_errorlogs = response_elasticsearch.search(index='responser-iptables-errorlogs', query={
                'term': {
                    'responser_name.keyword': iptable['_source']['responser_name']
                }
            }).raw
            if iptables_errorlogs['hits']['hits'].__len__() > 0:
                for iptables_errorlog in iptables_errorlogs['hits']['hits']:
                    response_elasticsearch.update(index='responser-iptables-errorlogs', id=iptables_errorlog['_id'], doc={
                        'responser_name': responser_name
                    })
        response_elasticsearch.update(index='responser-iptables', id=iptable['_id'], doc={
            'responser_name': responser_name,
            'responser_configuration': dumps(responser_configuration)
        })
        return {
            'type': 'iptables',
            'data': {
                'id': iptable['_id'],
                'responser_name': responser_name,
                'is_enabled': is_enabled_configuration,
                'target_ip_field': target_ip_field,
                'is_ruthless': is_ruthless,
                'limit_duration_minutes': limit_duration_minutes,
                'block_duration_minutes': block_duration_minutes,
                'advanced': is_enabled,
            },
            'reason': 'Success'
        }

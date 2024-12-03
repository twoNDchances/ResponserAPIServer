from flask import Blueprint
from flask_restful import Api
from .create import IPTablesCreation
from .list import IPTablesLists, IPTablesExecutionLists, IPTablesErrorlogLists
from .show import IPTablesManifests, IPTablesPayloadManifests
from .update import IPTablesModifications
from .delete import IPTablesTerminations, IPTablesExecutionTerminations, IPTablesEmptyErrorLogs


iptables_operation_blueprint = Blueprint(name='iptables_operation_blueprint', import_name=__name__)
iptables_operation_api = Api(app=iptables_operation_blueprint)

iptables_operation_api.add_resource(IPTablesCreation, '/create')
iptables_operation_api.add_resource(IPTablesLists, '/list')
iptables_operation_api.add_resource(IPTablesExecutionLists, '/list-executions')
iptables_operation_api.add_resource(IPTablesErrorlogLists, '/list-errorlogs/<string:responser_name>')
iptables_operation_api.add_resource(IPTablesManifests, '/show/<string:id>')
iptables_operation_api.add_resource(IPTablesPayloadManifests, '/show-payload/<string:id>')
iptables_operation_api.add_resource(IPTablesModifications, '/update/<string:id>')
iptables_operation_api.add_resource(IPTablesTerminations, '/delete/<string:responser_name>')
iptables_operation_api.add_resource(IPTablesExecutionTerminations, '/delete-execution/<string:id>')
iptables_operation_api.add_resource(IPTablesEmptyErrorLogs, '/empty-errorlogs/<string:responser_name>')

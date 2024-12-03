from flask import Blueprint
from flask_restful import Api
from .create import ModSecurityCreation
from .list import ModSecurityLists, ModSecurityExecutionLists, ModSecurityErrorlogLists
from .show import ModSecurityManifests, ModSecurityPayloadManifests
from .update import ModSecurityModifications
from .delete import ModSecurityTerminations, ModSecurityExecutionTerminations, ModSecurityEmptyErrorLogs


modsecurity_operation_blueprint = Blueprint(name='modsecurity_operation_blueprint', import_name=__name__)
modsecurity_operation_api = Api(app=modsecurity_operation_blueprint)

modsecurity_operation_api.add_resource(ModSecurityCreation, '/create')
modsecurity_operation_api.add_resource(ModSecurityLists, '/list')
modsecurity_operation_api.add_resource(ModSecurityExecutionLists, '/list-executions')
modsecurity_operation_api.add_resource(ModSecurityErrorlogLists, '/list-errorlogs/<string:responser_name>')
modsecurity_operation_api.add_resource(ModSecurityManifests, '/show/<string:id>')
modsecurity_operation_api.add_resource(ModSecurityPayloadManifests, '/show-payload/<string:id>')
modsecurity_operation_api.add_resource(ModSecurityModifications, '/update/<string:id>')
modsecurity_operation_api.add_resource(ModSecurityTerminations, '/delete/<string:responser_name>')
modsecurity_operation_api.add_resource(ModSecurityExecutionTerminations, '/delete-execution/<string:id>')
modsecurity_operation_api.add_resource(ModSecurityEmptyErrorLogs, '/empty-errorlogs/<string:responser_name>')

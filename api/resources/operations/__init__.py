from flask import Blueprint
from flask_restful import Api
from .create import ResourceCreations


resources_operation_blueprint = Blueprint(name='resources_operation_blueprint', import_name=__name__)

resources_operation_api = Api(app=resources_operation_blueprint)

resources_operation_api.add_resource(ResourceCreations, '/create')

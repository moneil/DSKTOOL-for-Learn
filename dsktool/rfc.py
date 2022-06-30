from syslog import LOG_CONS
from django.http import HttpResponseRedirect,HttpResponse
from bbrest import BbRest
import jsonpickle
import json
from dsktool.models import Messages
from dsktool.models import Logs
from django.shortcuts import render,redirect

class Rfc(object):
	"""
		Request for change class
		Record the reason for change in local sqllite3 database
	"""
	def __init__(self):
		super(Rfc, self).__init__()

	# save the message input for the Rfc
	def save_message(self, request, change_type):
		BB = self.get_bb(request)
		me_resp = BB.call(
			'GetUser',
			userId = "me",
			params = {'fields':'id, userName'},
			sync = True
			)

		me_json = me_resp.json()

		message = Messages(
			user_id = me_json['userName'],
			change_type = change_type,
			change_comment = request.GET.get('comment')
		)
		message.save()

		return message

	def save_log(self, **kwargs):
		json = self.solve_for(
			self,
			call_name = kwargs.get('call_name',""),
			userSearch = kwargs.get('userSearch',""),
			request = kwargs.get('request',""),
			crs = kwargs.get('crs',""),
			usr = kwargs.get('usr',""),
			updateValue = kwargs.get('updateValue',""),
		)

		print("KWARGS: ", kwargs.get('call_name',""))

		if kwargs.get('call_name',"") == "user":
			log = Logs(
				message = kwargs.get('message',{}),
				user_id = json['user_json']['userName'],
				external_id = json['user_json']['externalId'],
				availability_status = json['user_json']['availability']['available'],
				datasource_id = self.get_datasource(self, request=kwargs.get('request',""),dataSourceId=json['user_json']['dataSourceId']),
				state = kwargs.get('state',"")
			)
		elif kwargs.get('call_name',"") == "membership":
			log = Logs(
				message = kwargs.get('message',{}),
				user_id = json['enroll_json']['user']['userName'],
				course_id = json['course_json']['courseId'],
				external_id = json['enroll_json']['user']['externalId'],
				course_role = json['enroll_json']['courseRoleId'],
				availability_status = json['enroll_json']['availability']['available'],
				datasource_id = self.get_datasource(self, request=kwargs.get('request',""),dataSourceId=json['enroll_json']['dataSourceId']),
				state = kwargs.get('state',"")
			)
		elif kwargs.get('call_name',"") == "course":
			log = Logs(
				message = kwargs.get('message',{}),
				course_id = json['course_json']['courseId'],
				external_id = json['course_json']['externalId'],
				availability_status = json['course_json']['availability']['available'],
				datasource_id = self.get_datasource(self, request=kwargs.get('request',""),dataSourceId=json['course_json']['dataSourceId']),
				state = kwargs.get('state',"")
			)
		log.save()

	@staticmethod
	def get_bb(request):
		BB_JSON = request.session.get('BB_JSON')
		if (BB_JSON is None):
			BB = BbRest(KEY, SECRET, f"https://{LEARNFQDN}" )
			BB_JSON = jsonpickle.encode(BB)
			request.session['BB_JSON'] = BB_JSON
			request.session['target_view'] = 'users'
			return HttpResponseRedirect(reverse('get_auth_code'))
		else:
			BB = jsonpickle.decode(BB_JSON)
			if BB.is_expired():
				request.session['BB_JSON'] = None
				whoami(request)
			BB.supported_functions() # This and the following are required after
			BB.method_generator()    # unpickling the pickled object.

		return BB

	@staticmethod
	def get_user(self, **kwargs):
		BB = self.get_bb(kwargs.get('request',""))
		user_resp = BB.GetUser(
			userId = kwargs.get('userSearch',""),
			params = {
				'fields': 'id, userName, externalId, availability.available, dataSourceId'
			},
			sync=True
		)

		return {"user_json" : user_resp.json()}

	@staticmethod
	def get_membership(self, **kwargs):
		BB = self.get_bb(kwargs.get('request',""))
		enroll_resp = BB.GetMembership(
			courseId = kwargs.get('crs',""),
			userId = kwargs.get('usr',""),
			params = {
				'expand': 'user',
				'fields': 'id, courseId, userId, availability.available, dataSourceId, modified, created, courseRoleId, user.userName, user.name.given, user.name.middle, user.name.family, user.externalId, user.contact.email'
			},
			sync=True
		)

		course_resp = BB.GetCourse(
			courseId = kwargs.get('crs',""),
			params = {
				'fields':'id, courseId'
			},
			sync=True
		)

		return {
			"enroll_json" : enroll_resp.json(),
			"course_json" : course_resp.json()
		}

	@staticmethod
	def get_course(self, **kwargs):
		BB = self.get_bb(kwargs.get('request',""))
		course_resp = BB.GetCourse(
			courseId = kwargs.get('updateValue',""),
			params = {
				'fields': 'id, courseId, externalId, availability.available, dataSourceId'
			},
			sync=True
		)

		return {"course_json" : course_resp.json()}

	@staticmethod
	def get_datasource(self, **kwargs):
		BB = self.get_bb(kwargs.get('request',""))
		resp = BB.GetDataSource(
			dataSourceId = kwargs.get('dataSourceId',""),
			params = {
				'fields': 'id, externalId'
			},
			sync=True
		)

		return resp.json()['externalId']

	@staticmethod
	def solve_for(self, call_name: str, **kwargs):
		do = f"get_{call_name}"
		if hasattr(self, do) and callable(func := getattr(self, do)):
			return func(self, **kwargs)

	
from flask import Flask,request
from flask_restful import Api,Resource,abort
from flask_cors import CORS
import json
import jwt
import datetime
import psycopg2
from psycopg2 import Error
from psycopg2 import pool
import form_schema
from werkzeug.exceptions import BadRequest,Unauthorized,NotFound,Conflict
from jwt.exceptions import InvalidSignatureError,ExpiredSignatureError


app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
api = Api(app)
with open('secrets.json') as secrets_file:
    secrets = json.load(secrets_file)
access_token_secret_key = secrets["access_token_secret_key"]
pool = psycopg2.pool.SimpleConnectionPool(1,50,user=secrets["user"],password=secrets["password"],host=secrets["host"],port=secrets["port"],database=secrets["database"])

registration_form_schema = form_schema.RegistrationFormSchema()
log_in_form_schema = form_schema.LogInFormSchema()
classroom_creation_form_schema = form_schema.ClassroomCreationFormSchema()
assignment_creation_form_schema = form_schema.AssignmentCreationFormSchema()
score_updation_form_schema = form_schema.ScoreUpdationFormSchema()
score_publication_form_schema = form_schema.ScorePublicationFormSchema()

class Register(Resource):
	
	def post(self):
		
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			if registration_form_schema.validate(data):
				raise BadRequest("Invalid input")
				
			cursor.execute('CALL createUser(%s,%s,%s)',(data['email'],data['name'],data['password']))
			connection.commit()
			token = jwt.encode({"email":data['email'],"exp":datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=6)},access_token_secret_key,algorithm = "HS256")
			return {"access_token":token}
		except BadRequest as e:
			abort(400,message=e.description)	
		except Exception as e:
			if isinstance(e,Error) and 'USER WITH THIS EMAIL ALREADY EXISTS' in e.pgerror:
				abort(409,message = "This email is already in use")
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)		

		
class LogIn(Resource):

	def post(self):
		try:
			data = request.json
			connection = pool.getconn()
			cursor = connection.cursor()
			if log_in_form_schema.validate(data):
				raise BadRequest("Invalid input")
			cursor.callproc('emailExists',(data['email'],))
			result = cursor.fetchone()
			if result[0] == True:
				cursor.callproc('isCorrectPassword',(data['email'],data['password'],))
				result = cursor.fetchone()
				if result[0] == False:
					raise Unauthorized("Wrong password")
				token = jwt.encode({"email":data['email'],"exp":datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=6)},access_token_secret_key,algorithm = "HS256")
				return {"access_token":token}
			else:
				raise Unauthorized("User with this email does not exist")
		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized as e:
			abort(401,message=e.description)	
		except Exception as e:
			abort(400,message = "Could not process request")

		finally:
			cursor.close()
			pool.putconn(connection)

class UserInfo(Resource):
	
	def get(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getUserInfo',(payload['email'],))
			result = cursor.fetchone()
			return result[0]	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and 'USER NOT FOUND' in e.pgerror:
				abort(404,message='User info not found')
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)


class CreatedClassrooms(Resource):

	def get(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getCreatedClassRooms',(payload['email'],))
			result = cursor.fetchone()
			return {"classrooms":result[0]}	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')		
		except Exception as e:
			abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)



class JoinedClassrooms(Resource):

	def get(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getJoinedClassRooms',(payload['email'],))
			result = cursor.fetchone()
			return {"classrooms":result[0]}	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')		
		except Exception as e:
			abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)

class SummaryOfAssignments(Resource):

	def get(self,classroomCode):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getSummaryOfAssignmentsInClassRoom',(classroomCode,))
			summary = cursor.fetchone()
			accepting_submissions = []
			accepting_reviews = []
			graded = []
			for assignment in summary[0]:
				if assignment['current_state'] == 'accepting_submissions':
					accepting_submissions.append(assignment)
				elif assignment['current_state'] == 'accepting_reviews':
					accepting_reviews.append(assignment)
				else:
					graded.append(assignment)

			accepting_submissions.sort(key=lambda x: x['time_left_for_submission'], reverse=False)
			accepting_reviews.sort(key=lambda x: x['time_left_for_review'], reverse=False)
			graded.sort(key=lambda x: x['time_left_for_review'], reverse=True)						
			return {"assignments":accepting_submissions+accepting_reviews+graded}
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'INVALID CODE' in e.pgerror:
				abort(400,message = 'Invalid classroom code')	
			else:
				abort(400,message = 'Could not process request')
		finally:
			cursor.close()
			pool.putconn(connection)


class AssignmentDetail(Resource):
	
	def get(self,assignmentId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getAssignmentDetail',(assignmentId,))
			result = cursor.fetchone()
			return result[0]	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'ASSIGNMENT NOT FOUND' in e.pgerror:
				abort(404,message = 'Assignment not found')		
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)


class ReviewDetail(Resource):

	def get(self,reviewId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getReviewDetail',(reviewId,))
			result = cursor.fetchone()
			return result[0]	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'REVIEW NOT FOUND' in e.pgerror:
				abort(404,message = 'Review not found')			
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)

class CreateClassroom(Resource):
	def post(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			if classroom_creation_form_schema.validate(data):
				raise BadRequest("Invalid input")
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.execute('CALL createClassRoom(%s,%s,%s)',(payload['email'],data['name'],data['description']))
			connection.commit()
		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'USER NOT FOUND' in e.pgerror:
				abort(404,message = 'User not found')				
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)
				

class CreateAssignment(Resource):
	def post(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			if assignment_creation_form_schema.validate(data):
				raise BadRequest("Invalid input")
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.execute('CALL createAssignment(%s,%s,%s,%s,%s,%s,%s,%s,%s)',(payload['email'],data['code'],data['title'],data['description'],data['instructions'],data['max_score'],data['number_of_reviewers_per_submission'],data['submission_deadline'],data['review_deadline']))
			connection.commit()
		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'USER NOT FOUND' in e.pgerror:
				abort(404,message = 'User not found')
			elif isinstance(e,Error) and  'INVALID CODE' in e.pgerror:
				abort(400,message = 'Invalid classroom code')	
			elif isinstance(e,Error) and  'UNAUTHORIZED ACTION' in e.pgerror:
				abort(401,message = 'Not authorized to create assignment')		
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)

class SummaryOfSubmissions(Resource):
	
	def get(self,assignmentId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getSummaryOfSubmissionsInAssignment',(assignmentId,))
			result = cursor.fetchone()
			cursor.callproc('getAssignmentDetail',(assignmentId,))
			detail = cursor.fetchone()
			return {"current_state":detail[0]["current_state"],"submissions":result[0]}
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'ASSIGNMENT NOT FOUND' in e.pgerror:
				abort(404,message = 'Assignment not found')		
			else:
				abort(400,message = "Could not process request")		
		finally:
			cursor.close()
			pool.putconn(connection)


class SubmissionDetail(Resource):
	def get(self,submissionId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getSubmissionDetail',(submissionId,))
			result = cursor.fetchone()
			return result[0]	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'SUBMISSION NOT FOUND' in e.pgerror:
				abort(404,message = 'Submission not found')			
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)

class SubmissionGrade(Resource):
	def get(self,submissionId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getSubmissionGrade',(submissionId,))
			result = cursor.fetchone()
			return result[0]	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'GRADES NOT FOUND' in e.pgerror:
				abort(404,message = 'Grades not found')			
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)

class SummaryOfSubmissionReviews(Resource):
	def get(self,submissionId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])	
			cursor.callproc('getSummaryOfSubmissionReviews',(submissionId,))
			result = cursor.fetchone()
			return {"reviews":result[0]}	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)								


class UpdateFinalScore(Resource):
	
	def post(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			if score_updation_form_schema.validate(data):
				raise BadRequest("Invalid input")
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")	
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.execute('CALL updateFinalScore(%s,%s)',(data['submission_id'],data['final_score']))
			connection.commit()
		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized	as e:
			abort(401,message=e.description)
		except Exception as e:
			abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)

class PublishScore(Resource):
	def post(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			if score_publication_form_schema.validate(data):
				raise BadRequest("Invalid input")
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")	
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.execute('CALL publishScore(%s)',(data['assignment_id']))
			connection.commit()
		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized	as e:
			abort(401,message=e.description)	
		except Exception as e:
			if e is jwt.exceptions.InvalidSignatureError:
				abort(498,message='Invalid token')
			elif e is jwt.exceptions.ExpiredSignatureError:
				abort(401,message='Authorization required')
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)			


api.add_resource(Register,"/register")
api.add_resource(LogIn,"/login")
api.add_resource(UserInfo,"/userinfo")
api.add_resource(CreatedClassrooms,"/createdclassrooms")
api.add_resource(JoinedClassrooms,"/joinedclassrooms")
api.add_resource(SummaryOfAssignments,"/summaryofassignments/<string:classroomCode>")
api.add_resource(AssignmentDetail,"/assignmentdetail/<int:assignmentId>")
api.add_resource(ReviewDetail,"/reviewdetail/<int:reviewId>")
api.add_resource(CreateClassroom,"/createclassroom")
api.add_resource(CreateAssignment,"/createassignment")
api.add_resource(SummaryOfSubmissions,"/summaryofsubmissions/<int:assignmentId>")
api.add_resource(SubmissionDetail,"/submissiondetail/<int:submissionId>")
api.add_resource(SubmissionGrade,"/submissiongrade/<int:submissionId>")
api.add_resource(SummaryOfSubmissionReviews,"/summaryofsubmissionreviews/<int:submissionId>")
api.add_resource(UpdateFinalScore,"/updatefinalscore")
api.add_resource(PublishScore,"/publishscore")



if __name__ == "__main__": 
	app.run()	

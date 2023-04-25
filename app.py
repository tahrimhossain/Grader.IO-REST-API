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
import bcrypt
from dotenv import load_dotenv
import os


app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
api = Api(app)


with open('/etc/secrets/secrets.json') as secrets_file:
    secrets = json.load(secrets_file)

access_token_secret_key = secrets["access_token_secret_key"]
pool = psycopg2.pool.SimpleConnectionPool(1,50,user=secrets["user"],password=secrets["password"],host=secrets["host"],port=secrets["port"],database=secrets["database"])

registration_form_schema = form_schema.RegistrationFormSchema()
log_in_form_schema = form_schema.LogInFormSchema()
registration_form_schema = form_schema.RegistrationFormSchema()
log_in_form_schema = form_schema.LogInFormSchema()
classroom_creation_form_schema = form_schema.ClassroomCreationFormSchema()
assignment_creation_form_schema = form_schema.AssignmentCreationFormSchema()
score_updation_form_schema = form_schema.ScoreUpdationFormSchema()
score_publication_form_schema = form_schema.ScorePublicationFormSchema()
join_classroom_form_schema = form_schema.JoinClassroomFormSchema()
review_submission_form_schema = form_schema.ReviewSubmissionFormSchema()
save_submission_form_schema = form_schema.SaveSubmissionFormSchema()
submit_submission_form_schema = form_schema.SubmitSubmissionFormSchema()

class Register(Resource):
	
	def post(self):
		
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			if registration_form_schema.validate(data):
				raise BadRequest("Invalid input")
			
			data["password"] = bcrypt.hashpw(data["password"].encode("utf-8"),bcrypt.gensalt()).decode('utf-8')	
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
				cursor.callproc('getPassword',(data['email'],))
				result = cursor.fetchone()
				if bcrypt.checkpw(data["password"].encode("utf-8"),bytes(result[0],'utf-8')) == False:
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
			
			cursor.callproc('isUserCreatorOfClassroom',(classroomCode,payload['email'],))
			creator = cursor.fetchone()
			cursor.callproc('isUserParticipantInClassroom',(classroomCode,payload['email'],))
			participant = cursor.fetchone()
			
			if participant[0] == False and creator[0] == False:
				raise Unauthorized("Unauthorized action")

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
			
			cursor.callproc('isUserCreatorOfAssignment',(assignmentId,payload['email'],))
			creator = cursor.fetchone()

			cursor.callproc('isUserParticipantInAssignment',(assignmentId,payload['email'],))
			participant = cursor.fetchone()
			
			if creator[0] == False and participant[0] == False:
				raise Unauthorized("Unauthorized action")

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
			review_detail = cursor.fetchone()

			cursor.callproc('getSubmissionDetail',(review_detail[0]['submission_id'],))
			submission_detail = cursor.fetchone()
			
			cursor.callproc('isUserCreatorOfAssignment',(submission_detail[0]['assignment_id'],payload['email'],))
			creator_of_assignment = cursor.fetchone()

			cursor.callproc('isUserCreatorOfReview',(reviewId,payload['email'],))
			creator_of_review = cursor.fetchone()

			cursor.callproc('isUserCreatorOfSubmission',(review_detail[0]['submission_id'],payload['email'],))
			reciever_of_review = cursor.fetchone()

			
			if creator_of_assignment[0] == True or creator_of_review[0] == True:
				return review_detail[0]

			elif reciever_of_review[0] == True:
				review_detail[0]['name'] = None
				review_detail[0]['email'] = None
				return review_detail[0]

			else:		
				raise Unauthorized("Unauthorized action")
			
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
			cursor.callproc('createClassRoom',(payload['email'],data['name'],data['description'],))
			connection.commit()
			result = cursor.fetchone()
			return result[0]
		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			print(e)
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
			return {"message":"Successfully created"}
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
			
			cursor.callproc('isUserCreatorOfAssignment',(assignmentId,payload['email'],))
			creator = cursor.fetchone()
			
			if creator[0] == False:
				raise Unauthorized("Unauthorized action")

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
			submission_detail = cursor.fetchone()

			

			cursor.callproc('isUserCreatorOfAssignment',(submission_detail[0]['assignment_id'],payload['email'],))
			creator_of_assignment = cursor.fetchone()

			cursor.callproc('isUserReviewerOfSubmission',(submissionId,payload['email'],))
			reviewer_of_submission = cursor.fetchone()

			

			cursor.callproc('isUserCreatorOfSubmission',(submissionId,payload['email'],))
			creator_of_submission = cursor.fetchone()

			if creator_of_assignment[0] == True or creator_of_submission[0] == True:
				return submission_detail[0]
			elif reviewer_of_submission[0] == True:
				submission_detail[0]['name'] = None
				submission_detail[0]['email'] = None
				submission_detail[0]['user_id'] = None
				return submission_detail[0]
			else:
				raise Unauthorized("Unauthorized action")

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
			
			cursor.callproc('getSubmissionDetail',(submissionId,))
			submission_detail = cursor.fetchone()

			cursor.callproc('isUserCreatorOfAssignment',(submission_detail[0]['assignment_id'],payload['email'],))
			creator = cursor.fetchone()
			
			if creator[0] == False:
				raise Unauthorized("Unauthorized action")

			cursor.callproc('getAssignmentDetail',(submission_detail[0]['assignment_id'],))
			assignment_detail = cursor.fetchone()

			cursor.callproc('getSubmissionGrade',(submissionId,))
			result = cursor.fetchone()
			return {"assignment_state":assignment_detail[0]["current_state"],"grade":result[0]}

		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'GRADES NOT ASSIGNED' in e.pgerror:
				abort(404,message = 'Grades not assigned')
			elif isinstance(e,Error) and  'SUBMISSION NOT FOUND' in e.pgerror:
				abort(404,message = 'Submission not found')				
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
			
			cursor.callproc('getSubmissionDetail',(submissionId,))
			submission_detail = cursor.fetchone()

			cursor.callproc('isUserCreatorOfAssignment',(submission_detail[0]['assignment_id'],payload['email'],))
			creator = cursor.fetchone()
			
			if creator[0] == False:
				raise Unauthorized("Unauthorized action")

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
			
			cursor.callproc('getSubmissionDetail',(data['submission_id'],))
			submission_detail = cursor.fetchone()

			cursor.callproc('isUserCreatorOfAssignment',(submission_detail[0]['assignment_id'],payload['email'],))
			creator = cursor.fetchone()
			
			if creator[0] == False:
				raise Unauthorized("Unauthorized action")


			cursor.execute('CALL updateFinalScore(%s,%s)',(data['submission_id'],data['final_score']))
			connection.commit()
			return {"message":"Successfully updated"}
		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')		
		except Exception as e:
			print(e)
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
			
			cursor.callproc('isUserCreatorOfAssignment',(data['assignment_id'],payload['email'],))
			creator = cursor.fetchone()
			
			if creator[0] == False:
				raise Unauthorized("Unauthorized action")

			cursor.execute('CALL publishScore(%s)',(data['assignment_id'],))
			connection.commit()

			return {"message":"Successfully published"}

		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')			
		except Exception as e:
			print(e)
			abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)			


########################################################################################################################################################


class JoinClassroom(Resource):
	def post(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			
			if join_classroom_form_schema.validate(data):
				raise BadRequest("Invalid input")

			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")	
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.callproc('joinClassRoom',(payload['email'],data['classroom_code'],))
			connection.commit()
			result = cursor.fetchone()
			return result[0]
		except BadRequest as e:
			abort(400,message=e.description)	
		except Unauthorized	as e:
			abort(401,message=e.description)	
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')		
		except Exception as e:
			if isinstance(e,Error) and  'INVALID CODE' in e.pgerror:
				abort(400,message = 'Invalid classroom code')
			elif isinstance(e,Error) and  'USER NOT FOUND' in e.pgerror:
				abort(404,message = 'User not found')
			elif isinstance(e,Error) and  'CREATOR OF CLASSROOM CAN NOT JOIN AS PARTICIPANT' in e.pgerror:
				abort(409,message = "Creator of classroom can't join as participant")
			elif isinstance(e,Error) and 'USER IS ALREADY A PARTICIPANT IN THIS CLASSROOM' in e.pgerror:
				abort(409,message = "Already participant in classroom")
			else:
				abort(400,message = "Could not process request")		
		finally:
			cursor.close()
			pool.putconn(connection)

class CreatedSubmissionDetail(Resource):
	def get(self,assignmentId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			
			cursor.callproc('isUserParticipantInAssignment',(assignmentId,payload['email'],))
			participant = cursor.fetchone()

			if(participant[0] == False):
				raise Unauthorized("Unauthorized action")


			cursor.callproc('getAssignmentDetail',(assignmentId,))
			assignment_detail = cursor.fetchone()
			try:
				cursor.callproc('getCreatedSubmissionDetail',(assignmentId,payload['email'],))
				submission_detail = cursor.fetchone()
				return {"current_state_of_assignment":assignment_detail[0]["current_state"],"detail":submission_detail[0]}		
			except Exception as e:
				return {"current_state_of_assignment":assignment_detail[0]["current_state"],"detail":None}					
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

class SummaryOfReviewsGottenForCreatedSubmission(Resource):
	def get(self,assignmentId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.callproc('getSummaryOfReviewsForCreatedSubmission',(assignmentId,payload['email'],))
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


class SummaryOfAssignedSubmissionsForReview(Resource):
	def get(self,assignmentId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.callproc('getSummaryOfAssignedSubmissionsForReview',(assignmentId,payload['email'],))
			result = cursor.fetchone()
			return {"submissions":result[0]}	
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

class AssignmentGrade(Resource):
	def get(self,assignmentId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			
			cursor.callproc('isUserParticipantInAssignment',(assignmentId,payload['email'],))
			participant = cursor.fetchone()

			if participant[0] == False:
				raise Unauthorized("User not a participant in assignment")

			cursor.callproc('getAssignmentGrade',(assignmentId,payload['email'],))
			grade = cursor.fetchone()
			return grade[0]	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'GRADE NOT ASSIGNED' in e.pgerror:
				abort(404,message = 'Grade not assigned')
			elif isinstance(e,Error) and  'USER NOT FOUND' in e.pgerror:
				abort(404,message = 'User not found')
			elif isinstance(e,Error) and  'ASSIGNMENT NOT FOUND' in e.pgerror:
				abort(404,message = 'Assignment not found')					
			else:
				abort(400,message = "Could not process request")	
		finally:
			cursor.close()
			pool.putconn(connection)



class CreatedReviewForSubmission(Resource):
	def get(self,submissionId):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			
			cursor.callproc('getSubmissionDetail',(submissionId,))
			submission_detail = cursor.fetchone()

			cursor.callproc('getAssignmentDetail',(submission_detail[0]['assignment_id'],))
			assignment_detail = cursor.fetchone()
			
			try:
				cursor.callproc('getCreatedReviewForSubmission',(submissionId,payload['email'],))
				review_detail = cursor.fetchone()
				return {"current_state_of_assignment":assignment_detail[0]["current_state"],"max_score":assignment_detail[0]["max_score"],"detail":review_detail[0]}		
			except Exception as e:
				return {"current_state_of_assignment":assignment_detail[0]["current_state"],"max_score":assignment_detail[0]["max_score"],"detail":None}					
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')	
		except Exception as e:
			if isinstance(e,Error) and  'ASSIGNMENT NOT FOUND' in e.pgerror:
				abort(404,message = 'Submission not found')	
			elif isinstance(e,Error) and  'SUBMISSION NOT FOUND' in e.pgerror:
				abort(404,message = 'Submission not found')			
			else:
				abort(400,message = "Could not process request")
		finally:
			cursor.close()
			pool.putconn(connection)


class SubmitReview(Resource):
	def post(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			#validate sent data here
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")	
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.execute('CALL submitReview(%s,%s,%s,%s)',(data['submission_id'],payload['email'],data['assigned_score'],data['content']))
			connection.commit()
			return {"message":"Successfully submitted"}
		except Unauthorized	as e:
			abort(401,message=e.description)	
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')			
		except Exception as e:
			if isinstance(e,Error) and  'USER NOT FOUND' in e.pgerror:
				abort(404,message = 'User not found')
			elif isinstance(e,Error) and 'UNAUTHORIZED ACTION' in e.pgerror:
				abort(401,message="Unauthorized action")
			else:
				abort(400,message = "Could not process request")			
		finally:
			cursor.close()
			pool.putconn(connection)

	
class SaveSubmission(Resource):
	def post(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json

			if save_submission_form_schema.validate(data):
				raise BadRequest("Invalid input")
			
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")	
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.execute('CALL saveSubmission(%s,%s,%s)',(data['assignment_id'],payload['email'],data['content']))
			connection.commit()
			return {"message":"Successfully saved"}
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
			elif isinstance(e,Error) and 'UNAUTHORIZED ACTION' in e.pgerror:
				abort(401,message="Unauthorized action")
			elif isinstance(e,Error) and 'INVALID ASSIGNMENT ID' in e.pgerror:
				abort(401,message="Invalid assignment id")
			else:
				abort(400,message = "Could not process request")			
		finally:
			cursor.close()
			pool.putconn(connection)


class SubmitSubmission(Resource):
	def post(self):
		try:
			connection = pool.getconn()
			cursor = connection.cursor()
			data = request.json
			
			if submit_submission_form_schema.validate(data):
				raise BadRequest("Invalid input")

			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")	
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			cursor.execute('CALL submitSubmission(%s,%s,%s)',(data['assignment_id'],payload['email'],data['content']))
			connection.commit()
			return {"message":"Successfully submitted"}
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
			elif isinstance(e,Error) and 'UNAUTHORIZED ACTION' in e.pgerror:
				abort(401,message="Unauthorized action")
			elif isinstance(e,Error) and 'INVALID ASSIGNMENT ID' in e.pgerror:
				abort(401,message="Invalid assignment id")
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
api.add_resource(JoinClassroom,"/joinclassroom")
api.add_resource(CreatedSubmissionDetail,"/createdsubmissiondetail/<int:assignmentId>")
api.add_resource(SummaryOfReviewsGottenForCreatedSubmission,"/summaryofreviewsgottenforcreatedsubmission/<int:assignmentId>")
api.add_resource(SummaryOfAssignedSubmissionsForReview,"/summaryofassignedsubmissionsforreview/<int:assignmentId>")
api.add_resource(AssignmentGrade,"/assignmentgrade/<int:assignmentId>")
api.add_resource(CreatedReviewForSubmission,"/createdreviewforsubmission/<int:submissionId>")
api.add_resource(SubmitReview,"/submitreview")
api.add_resource(SaveSubmission,"/savesubmission")
api.add_resource(SubmitSubmission,"/submitsubmission")



if __name__ == "__main__": 
	app.run()	

from marshmallow import fields, Schema

class  RegistrationFormSchema(Schema):
	email = fields.Email(required=True)
	name = fields.Str(required=True)
	password = fields.Str(required=True)

	
class LogInFormSchema(Schema):
	email = fields.Email(required=True)
	password = fields.Str(required=True)


class ClassroomCreationFormSchema(Schema):
	name = fields.Str(required=True)
	description = fields.Str(required=True)


class AssignmentCreationFormSchema(Schema):
	code = fields.Str(required=True)
	title = fields.Str(required=True)
	description = fields.Str(required=True)
	instructions = fields.Str(required=True)
	max_score = fields.Int(required=True)
	number_of_reviewers_per_submission = fields.Int(required=True)
	submission_deadline = fields.DateTime(required=True)
	review_deadline = fields.DateTime(required=True)
	
class ScoreUpdationFormSchema(Schema):
	submission_id = fields.Int(required=True)
	final_score = fields.Int(required=True)

class ScorePublicationFormSchema(Schema):
	assignment_id = fields.Int(required=True)


class JoinClassroomFormSchema(Schema):
	classroomCode = fields.Str(required=True)

class ReviewSubmissionFormSchema(Schema):
	submission_id = fields.Int(required=True)
	assigned_score = fields.Int(required=True)
	content = fields.Str(required=True)

class SaveSubmissionFormSchema(Schema):
	assignment_id = fields.Int(required = True)
	content = fields.Str(required = True)

class SubmitSubmissionFormSchema(Schema):
	assignment_id = fields.Int(required = True)
	content = fields.Str(required = True)				
						
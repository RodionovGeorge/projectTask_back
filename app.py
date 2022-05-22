import secrets
import smtplib
import string
import base64
import uuid
import subprocess
import os

from flask import Flask, request, render_template, after_this_request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, desc, or_, and_
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import select, exists
from flask_restful import Resource, Api
from flask_mail import Mail, Message
from smtplib import SMTPException
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from pdf2image import convert_from_path
from PIL import Image
from pdf2image.exceptions import (
    PDFInfoNotInstalledError,
    PDFPageCountError,
    PDFSyntaxError
)
from functools import wraps
import errors
from io import BytesIO
import constants
import datetime
import traceback


app = Flask(__name__)
api = Api(app, errors=errors.errorsDict)
db_password = os.environ.get('DB_KEY')
mail_password = os.environ.get('MAIL_PASSWORD')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:' + str(db_password) + '@postgres/projectTask_db'
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='etuprojecttask@gmail.com',
    MAIL_PASSWORD=str(mail_password),
    MAIL_DEFAULT_SENDER='etuprojecttask@gmail.com'
)
db = SQLAlchemy(app, session_options={"autoflush": False})
mail = Mail(app)
bcrypt = Bcrypt(app)

# DB tables

user_role_table = db.Table('user_role',
                           db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                           db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
                           )


class User(db.Model):
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    email = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)
    university_group = db.Column(db.Text, nullable=False, default='-1')
    avatar_url = db.Column(db.Text, nullable=False, default=constants.CONST_SERVER_URL + '/files/blank-profile-picture.png')
    roles = db.relationship('Role',
                            secondary=user_role_table,
                            lazy='joined',
                            backref=db.backref('users', lazy=True)
                            )
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_date = db.Column(db.DateTime, nullable=True, default=datetime.datetime.utcnow())
    first_name = db.Column(db.Text, nullable=False)
    middle_name = db.Column(db.Text, nullable=False)
    last_name = db.Column(db.Text, nullable=False)
    CSRF_token = db.relationship('CSRFToken',
                                 backref='user',
                                 cascade='all, delete-orphan',
                                 uselist=False,
                                 lazy='joined'
                                 )
    session_token = db.relationship('SessionToken',
                                    backref='user',
                                    cascade='all, delete-orphan',
                                    uselist=False,
                                    lazy='joined'
                                    )
    activating_code = db.relationship('ActivateUserCode',
                                      backref='user',
                                      cascade='all, delete-orphan',
                                      uselist=False,
                                      lazy=True
                                      )
    new_password_code = db.relationship('NewPasswordCode',
                                        backref='user',
                                        cascade='all, delete-orphan',
                                        uselist=False,
                                        lazy=True
                                        )
    problems = db.relationship('Problem',
                               backref='author',
                               cascade='all, delete-orphan',
                               lazy=True
                               )
    sessions = db.relationship('Session',
                               backref='student',
                               cascade='all, delete-orphan',
                               lazy=True
                               )
    commentaries = db.relationship('Commentary',
                                   backref='author',
                                   cascade='all, delete-orphan',
                                   lazy=True
                                   )


    def for_transmitting(self):
        role_titles = []
        for role in self.roles:
            role_titles.append(role.title)
        return {
            'roles': role_titles,
            'id': self.id,
            'email': self.email,
            'avatarURL': self.avatar_url,
            'accountActivated': self.confirmed,
            'firstName': self.first_name,
            'middleName': self.middle_name,
            'lastName': self.last_name
        }

    def full_name_with_dots(self):
        if self.middle_name == '':
            return self.last_name + ' ' + self.first_name[0] + '.'
        return self.last_name + ' ' + self.first_name[0] + '. ' + self.middle_name[0] + '.'

    def full_name(self):
        return self.last_name + ' ' + self.first_name + ' ' + self.middle_name

    def __init__(self, user_information):
        self.first_name = user_information.get('firstName')
        self.middle_name = user_information.get('middleName')
        self.last_name = user_information.get('lastName')
        self.password = user_information.get('password')
        self.email = user_information.get('email')
        self.university_group = user_information.get('group')
        self.roles = Role.query.filter(Role.title.in_(['Ученик', 'Учитель'])).all()


class SessionToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, token):
        self.token = token


class CSRFToken(db.Model):
    __tablename__ = 'csrf_token'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, token):
        self.token = token


class ActivateUserCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.Text, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    expiration_date = db.Column(db.DateTime, nullable=False)
    last_user_attempt_time = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, code):
        self.code = code
        self.creation_date = datetime.datetime.utcnow()
        self.expiration_date = datetime.datetime.utcnow() + datetime.timedelta(
                                        seconds=constants.CONST_ACTIVATING_CODE_TTL
                                        )


class NewPasswordCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.Text, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())
    expiration_date = db.Column(db.DateTime, nullable=False)
    last_user_attempt_time = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, code):
        self.code = code
        self.creation_date = datetime.datetime.utcnow()
        self.expiration_date = datetime.datetime.utcnow() + datetime.timedelta(
                                        seconds=constants.CONST_NEW_PASSWORD_CODE_TTL
                                        )


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)

    def __init__(self, title):
        self.title = title


class ProblemStatus(db.Model):
    __tablename__ = 'problem_status'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text)

    def __init__(self, title):
        self.title = title


class ProblemComplexity(db.Model):
    __tablename__ = 'problem_complexity'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text)

    def __init__(self, title):
        self.title = title


class TeacherFeedbackStatus(db.Model):
    __tablename__ = 'teacher_feedback_status'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)

    def __init__(self, title):
        self.title = title


class StudentAttemptStatus(db.Model):
    __tablename__ = 'student_attempt_status'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)

    def __init__(self, title):
        self.title = title


class SessionStatus(db.Model):
    __tablename__ = 'session_status'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)

    def __init__(self, title):
        self.title = title


class SolutionDegree(db.Model):
    __tablename__ = 'solution_degree'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)

    def __init__(self, title):
        self.title = title


class Commentary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    commentary_time = db.Column(db.DateTime, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attempt_id = db.Column(db.Integer, db.ForeignKey('attempt.id'))
    is_new_for_student = db.Column(db.Boolean)
    is_new_for_teacher = db.Column(db.Boolean)

    def __init__(self, text, author_is_teacher):
        self.text = text
        self.is_new_for_student = author_is_teacher
        self.is_new_for_teacher = not author_is_teacher
        self.commentary_time = datetime.datetime.utcnow()

    def for_transmitting(self):
        return {
            'commentaryID': self.id,
            'commentaryText': self.text,
            'commentaryDate': date_to_str(self.commentary_time),
            'authorID': self.author_id
        }


class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    student_attempt = db.relationship('StudentAttempt',
                                      backref='attempt',
                                      lazy='joined',
                                      cascade='all, delete-orphan',
                                      uselist=False
                                      )
    teacher_feedback = db.relationship('TeacherFeedback',
                                       backref='attempt',
                                       lazy='joined',
                                       cascade='all, delete-orphan',
                                       uselist=False
                                       )
    commentaries = db.relationship('Commentary',
                                   backref='attempt',
                                   lazy='joined',
                                   cascade='all, delete-orphan'
                                   )

    @hybrid_property
    def has_new_commentaries_for_student(self):
        return db.session.query(func.count(Commentary.id))\
            .where(and_(Commentary.attempt_id==self.id, Commentary.is_new_for_student==True))\
            .scalar()

    @has_new_commentaries_for_student.expression
    def has_new_commentaries_for_student(cls):
        return select(func.count(Commentary.id))\
            .where(and_(Commentary.attempt_id==cls.id, Commentary.is_new_for_student==True))\
            .label('has_new_commentaries_for_student')

    @hybrid_property
    def has_new_commentaries_for_teacher(self):
        return db.session.query(func.count(Commentary.id))\
            .where(and_(Commentary.attempt_id==self.id, Commentary.is_new_for_teacher==True))\
            .scalar()

    @has_new_commentaries_for_teacher.expression
    def has_new_commentaries_for_teacher(cls):
        return select(func.count(Commentary.id))\
            .where(and_(Commentary.attempt_id==cls.id, Commentary.is_new_for_teacher==True))\
            .label('has_new_commentaries_for_student')

    def __init__(self, student_attempt):
        self.student_attempt = student_attempt


class TeacherFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    solution_degree_id = db.Column(db.Integer, db.ForeignKey('solution_degree.id'), nullable=False)
    solution_degree = db.relationship('SolutionDegree', backref='feedbacks', lazy='joined')
    feedback_time = db.Column(db.DateTime, nullable=False)
    creation_time = db.Column(db.DateTime)
    teacher_commentary = db.Column(db.Text, nullable=False)
    file_url = db.Column(db.Text, nullable=False)
    attempt_id = db.Column(db.Integer, db.ForeignKey('attempt.id'))
    status_id = db.Column(db.Integer, db.ForeignKey('teacher_feedback_status.id'), nullable=False)
    status = db.relationship('TeacherFeedbackStatus', backref='feedbacks', lazy='joined')

    def __init__(self, solution_degree, teacher_commentary, file_url):
        self.feedback_time = datetime.datetime.utcnow()
        self.creation_time = datetime.datetime.utcnow()
        self.file_url = file_url
        self.teacher_commentary = teacher_commentary
        self.solution_degree = solution_degree

    def for_transmitting(self, is_teacher):
        if not is_teacher and self.status.title == 'Черновик отзыва':
            return None
        return {
            'id': self.id,
            'decisionStage': self.solution_degree.title,
            'checkDate': date_to_str(self.feedback_time),
            'problemFileURL': self.file_url,
            'teacherCommentary': self.teacher_commentary
        }


class StudentAttempt(db.Model):
    __tablename__ = 'student_attempt'
    id = db.Column(db.Integer, primary_key=True)
    file_url = db.Column(db.Text, nullable=False)
    creation_time = db.Column(db.DateTime)
    last_editing_time = db.Column(db.DateTime, nullable=False)
    attempt_id = db.Column(db.Integer, db.ForeignKey('attempt.id'))
    status_id = db.Column(db.Integer, db.ForeignKey('student_attempt_status.id'), nullable=False)
    status = db.relationship('StudentAttemptStatus', backref='attempts', lazy='joined')

    def __init__(self, file_url):
        self.file_url = file_url
        self.last_editing_time = datetime.datetime.utcnow()
        self.creation_time = datetime.datetime.utcnow()
        self.status_id = StudentAttemptStatus.query.filter_by(title='Попытка не просмотрена учителем').first().id


    def for_transmitting(self):
        return {
            'fileURL': self.file_url,
            'dateOfLastChange': date_to_str(self.last_editing_time),
            'status': self.status.title,
            'id': self.id
        }


class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status_id = db.Column(db.Integer, db.ForeignKey('session_status.id'), nullable=False)
    status = db.relationship('SessionStatus', backref='sessions', lazy='joined')
    problem_id = db.Column(db.Text, db.ForeignKey('problem.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attempts = db.relationship('Attempt', backref='session', lazy=True, cascade='all, delete-orphan')

    @hybrid_property
    def unchecked_attempt_count(self):
        q1 = db.session.query(func.count(Attempt.id))\
            .where(and_(Attempt.session_id==self.id, Attempt.teacher_feedback==None))\
            .scalar()
        q2 = db.session.query(func.count(Attempt.id)). \
            join(TeacherFeedback, TeacherFeedback.attempt_id == Attempt.id). \
            join(TeacherFeedbackStatus, TeacherFeedbackStatus.id == TeacherFeedback.status_id). \
            where(and_(Attempt.session_id == self.id, TeacherFeedbackStatus.title == 'Черновик отзыва')).\
            scalar()
        return q1 + q2


    @unchecked_attempt_count.expression
    def unchecked_attempt_count(cls):
        q1 = db.session.query(func.count(Attempt.id).label('s')).\
            join(TeacherFeedback, TeacherFeedback.attempt_id==Attempt.id).\
            join(TeacherFeedbackStatus, TeacherFeedbackStatus.id==TeacherFeedback.status_id).\
            where(and_(Attempt.session_id==cls.id, TeacherFeedbackStatus.title=='Черновик отзыва'))
        q2 = db.session.query(func.count(Attempt.id).label('s')).where(and_(Attempt.session_id==cls.id, Attempt.teacher_feedback==None))
        union = q1.union_all(q2).subquery()
        return select([func.count(union.c.s)], from_obj=union)\
            .label('unchecked_attempt_count')

    @hybrid_property
    def has_new_commentary_for_teacher(self):
        return db.session.query(func.count(Commentary.id))\
            .join(Attempt)\
            .where(and_(Commentary.attempt_id==Attempt.id, Attempt.session_id==self.id, Commentary.is_new_for_teacher==True))\
            .scalar()

    @has_new_commentary_for_teacher.expression
    def has_new_commentary_for_teacher(cls):
        return select(func.count(Commentary.id)) \
            .join(Attempt) \
            .where(and_(Commentary.attempt_id==Attempt.id, Attempt.session_id == cls.id, Commentary.is_new_for_teacher == True)) \
            .label('has_new_commentary_for_teacher')

    def __init__(self, status, student_attempt, student, problem):
        self.status = status
        self.student = student
        self.problem = problem
        self.attempts.append(Attempt(student_attempt))

    def add_attempt(self, student_attempt):
        self.attempts.append(Attempt(student_attempt))

    def has_new_content_for_student(self):
        unchecked_teacher_feedback_count = db.session.query(func.count(TeacherFeedback.id))\
            .join(Attempt)\
            .join(TeacherFeedbackStatus)\
            .where(and_(Attempt.session_id==self.id, TeacherFeedbackStatus.title=='Отзыв не просмотрен учеником'))\
            .scalar()
        unchecked_commentary_count = db.session.query(func.count(Commentary.id))\
            .join(Attempt)\
            .where(and_(Attempt.session_id==self.id, Commentary.is_new_for_student==True))\
            .scalar()
        return unchecked_teacher_feedback_count > 0 or unchecked_commentary_count > 0

class Problem(db.Model):
    id = db.Column(db.Text, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.Text, nullable=False)
    discipline = db.Column(db.Text, nullable=False)
    problem_file_URL = db.Column(db.Text, nullable=False)
    author_commentary = db.Column(db.Text, nullable=False)
    creation_date = db.Column(db.DateTime)
    start_date_of_making_decision = db.Column(db.DateTime, nullable=False)
    end_date_of_making_decision = db.Column(db.DateTime, nullable=False)
    problem_status_id = db.Column(db.Integer, db.ForeignKey('problem_status.id'), nullable=False)
    problem_status = db.relationship('ProblemStatus', backref='problems', lazy='joined')
    problem_complexity_id = db.Column(db.Integer, db.ForeignKey('problem_complexity.id'))
    problem_complexity = db.relationship('ProblemComplexity', backref='problems', lazy='joined')
    last_admitting_attempt = db.Column(db.DateTime)
    rejection_reason = db.Column(db.Text)
    "Поле, специльно введенное для возвращения верного статуса после снятия блокировки(как узнать, было Принята или Скрыта)" \
    "По умолчанию False, поскольку если задачу одобрит админ, то она получит статус Принята" \
    "Если задачу отклонят, то это поле бессмысленно и просто будет False"
    is_hide = db.Column(db.Boolean, default=False)
    sessions = db.relationship('Session', backref='problem', cascade='all, delete-orphan')

    @hybrid_property
    def unchecked_attempt_count(self):
        q1 = db.session.query(func.count(Attempt.id))\
            .join(Session, Session.problem_id == self.id) \
            .where(and_(Attempt.session_id==Session.id, Attempt.teacher_feedback==None))\
            .scalar()
        q2 = db.session.query(func.count(Attempt.id)). \
            join(Session, Session.problem_id == self.id). \
            join(TeacherFeedback, TeacherFeedback.attempt_id == Attempt.id). \
            join(TeacherFeedbackStatus, TeacherFeedbackStatus.id == TeacherFeedback.status_id). \
            where(and_(Attempt.session_id == Session.id, TeacherFeedbackStatus.title == 'Черновик отзыва')).\
            scalar()
        return q1 + q2

    @unchecked_attempt_count.expression
    def unchecked_attempt_count(cls):
        q1 = db.session.query(func.count(Attempt.id).label('s')). \
            join(Session, Session.problem_id == cls.id). \
            join(TeacherFeedback, TeacherFeedback.attempt_id == Attempt.id). \
            join(TeacherFeedbackStatus, TeacherFeedbackStatus.id == TeacherFeedback.status_id). \
            where(and_(Attempt.session_id == Session.id, TeacherFeedbackStatus.title == 'Черновик отзыва'))
        q2 = db.session.query(func.count(Attempt.id).label('s')). \
            join(Session, Session.problem_id == cls.id). \
            where(and_(Attempt.session_id == Session.id, Attempt.teacher_feedback == None))
        union = q1.union_all(q2).subquery()
        return select([func.count(union.c.s)], from_obj=union) \
            .label('unchecked_attempt_count')

    def __init__(self, problem_inf):
        self.id = generate_code(constants.CONST_PROBLEM_ID_LENGTH)
        self.author = problem_inf.get('author')
        self.title = problem_inf.get('title')
        self.discipline = problem_inf.get('discipline')
        self.problem_file_URL = problem_inf.get('problemFileURL')
        self.author_commentary = problem_inf.get('authorCommentary')
        self.start_date_of_making_decision = problem_inf.get('startDate')
        self.end_date_of_making_decision = problem_inf.get('endDate')
        self.problem_status = problem_inf.get('status')
        self.creation_date = datetime.datetime.utcnow()

    def can_be_modified(self):
        return self.problem_status.title == 'Принята' or self.problem_status.title == 'Скрыта'


class ImagePath(db.Model):
    __tablename__ = 'image_path'
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.Text, nullable=False)
    student_attempt_id = db.Column(db.Integer, db.ForeignKey('student_attempt.id'), nullable=False)
    student_attempt = db.relationship(
        'StudentAttempt',
        backref=db.backref('images', cascade='all, delete-orphan'),
        lazy='joined'
    )

    def __init__(self, problem_path):
        self.path = problem_path


class Information(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.Text, nullable=False)
    text = db.Column(db.Text, nullable=False)


class ProblemDiscipline(db.Model):
    __tablename__ = 'problem_discipline'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.Text, nullable=False)

    def __init__(self, label):
        self.label = label

    def for_transmitting(self):
        return {
            'id': self.id,
            'label': self.label
        }


#db.create_all()
migrate = Migrate(app, db, compare_type=True)


# Functions
def generate_code(code_length):
    activating_code = ''
    activating_code = activating_code.join(
        secrets.choice(
            string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(code_length)
    )
    return activating_code


def generate_session_token():
    return secrets.token_urlsafe(constants.CONST_SESSION_TOKEN_LENGTH)


def generate_message(template, inf_for_template, recipients):
    msg = Message('Проект "Задача"', recipients=recipients)
    msg.html = render_template(
        template,
        obj=inf_for_template
    )
    return msg


def new_csrf_token_for_user(user):
    csrf_code = generate_code(constants.CONST_CSRF_TOKEN_LENGTH)
    if user.CSRF_token is None:
        csrf_token = CSRFToken(
            bcrypt.generate_password_hash(
                csrf_code.encode('utf8')
            ).decode('utf8')
        )
        user.CSRF_token = csrf_token
    else:
        user.CSRF_token.token = bcrypt.generate_password_hash(
                csrf_code.encode('utf8')
            ).decode('utf8')
    return csrf_code


def date_to_str(d):
    return d.astimezone(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S %z')


# API


def session_token_check(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            session_token = request.cookies.get('session-token')
            if session_token is None:
                raise errors.AuthenticationError()
            user = User.query.join(SessionToken).filter(SessionToken.token == session_token).first()
            if user is None:
                raise errors.AuthenticationError()
            return f(*args, user, **kwargs)
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()
    return wrapper


def csrf_token_check(f):
    @wraps(f)
    @session_token_check
    def wrapper(*args, **kwargs):
        try:
            data = request.get_json()
            user = args[len(args) - 1]
            csrf_token = data.get('csrfToken')
            if csrf_token is None:
                raise errors.IncorrectRequestError()
            if bcrypt.check_password_hash(user.CSRF_token.token, csrf_token.encode('utf8')):
                response = f(*args, data, **kwargs)
                if response[1] < 400:
                    data = response[0]
                    csrf_code = new_csrf_token_for_user(user)
                    data['csrfToken'] = csrf_code
                    db.session.commit()
                    return data, 200
            else:
                raise errors.AuthenticationError()
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()
    return wrapper


def role_check(user, *args):
    for role in user.roles:
        if role.title in args:
            return True
    return False


class Logout(Resource):
    method_decorators = [session_token_check]

    def get(*args, **kwargs):
        @after_this_request
        def delete_session_cookie(response):
            response.set_cookie('session-token',
                                value='',
                                max_age=0,
                                httponly=True
                                )
            return response
        try:
            user = args[len(args) - 1]
            del user.CSRF_token
            del user.session_token
            db.session.commit()
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


"""Когда пользователь перезагружает страницу, нужно загрузить данные с сервера по новой (+ обновить cookie)"""
class RestoreUserData(Resource):
    method_decorators = [session_token_check]

    def get(*args, **kwargs):
        @after_this_request
        def delete_cookie(response):
            if response.status_code != 200:
                response.set_cookie('session-token',
                                    value='',
                                    max_age=0,
                                    httponly=True
                                    )
            else:
                response.set_cookie('session-token',
                                    value=new_session_token,
                                    max_age=constants.CONST_SESSION_TOKEN_TTL,
                                    httponly=True
                                    )
            return response
        try:
            user = args[len(args) - 1]
            new_session_token = generate_session_token()
            user.session_token.token = new_session_token
            db.session.commit()
            return {
                'message': 'success',
                'userData': user.for_transmitting()
            }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()


class Login(Resource):
    def post(self):
        @after_this_request
        def set_session_cookie(response):
            if response.status_code == 200:
                response.set_cookie('session-token',
                                    value=session_token,
                                    max_age=constants.CONST_SESSION_TOKEN_TTL,
                                    httponly=True
                                    )
            return response
        try:
            user_data = request.get_json()
            user_data['login'] = user_data['login'].lower()
            user = User.query.filter_by(email=user_data.get('login')).first()
            if user is None:
                raise errors.IncorrectEmailAddressError()
            if bcrypt.check_password_hash(user.password, user_data.get('password').encode('utf8')):
                session_token = generate_session_token()
                user.session_token = SessionToken(session_token)
                csrf_code = new_csrf_token_for_user(user)
                db.session.commit()
                return {
                    'message': 'success',
                    'csrfToken': csrf_code,
                    'userData': user.for_transmitting()
                }, 200
            else:
                raise errors.IncorrectPasswordError()
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()


class Registration(Resource):
    def post(self):
        try:
            user_data = request.get_json()
            user_data['email'] = user_data['email'].lower()
            check_user_exists = User.query.filter_by(
                email=user_data.get('email')
            ).first()
            if check_user_exists is not None:
                raise errors.UserAlreadyExistsError()
            user_data['password'] = bcrypt.generate_password_hash(user_data.get('password').encode('utf8')).decode('utf8')
            new_user = User(user_data)
            act_code = generate_code(constants.CONST_ACTIVATING_CODE_LENGTH)
            new_user.activating_code = ActivateUserCode(bcrypt.generate_password_hash(act_code).decode('utf8'))
            msg = generate_message(
                'template_for_activating_account.html',
                {'code': act_code, 'user_name': new_user.first_name},
                [new_user.email]
            )
            mail.send(msg)
            db.session.add(new_user)
            db.session.commit()
            return {'message': 'success'}, 201
        except smtplib.SMTPRecipientsRefused:
            raise errors.IncorrectEmailAddressError()
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()
        except SMTPException:
            traceback.print_exc()
            raise errors.SMTPError()


class ActivatingCodeCheck(Resource):
    def post(self):
        try:
            data = request.get_json()
            data['email'] = data['email'].lower()
            user = User.query.filter_by(email=data.get('email')).first()
            if user.confirmed is True:
                errors.UserAlreadyActivated()
            if user.activating_code.creation_date + datetime.timedelta(
                seconds=constants.CONST_ACTIVATING_CODE_REQUEST_INTERVAL
            ) >= datetime.datetime.utcnow():
                raise errors.ARTimeIntervalError()
            act_code = generate_code(constants.CONST_ACTIVATING_CODE_LENGTH)
            user.activating_code = ActivateUserCode(
                bcrypt.generate_password_hash(act_code.encode('utf8')).decode('utf8')
            )
            msg = generate_message(
                'template_for_activating_account.html',
                {'code': act_code, 'user_name': user.first_name},
                [user.email]
            )
            mail.send(msg)
            db.session.commit()
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()
        except SMTPException:
            raise errors.SMTPError()

    def put(self):
        try:
            data = request.get_json()
            data['email'] = data['email'].lower()
            user = User.query.filter_by(email=data.get('email')).first()
            current_time = datetime.datetime.utcnow()
            if user.confirmed is True:
                raise errors.UserAlreadyActivated()
            if current_time > user.activating_code.expiration_date:
                raise errors.CodeExpiredError()
            last_attempt_time = user.activating_code.last_user_attempt_time
            if last_attempt_time is not None and last_attempt_time + datetime.timedelta(
                seconds=constants.CONST_ACTIVATING_CODE_CHECK_INTERVAL
            ) > current_time:
                raise errors.ACTimeIntervalError()
            if bcrypt.check_password_hash(user.activating_code.code, data.get('code').encode('utf8')):
                user.confirmed = True
                user.confirmed_date = current_time
                del user.activating_code
                db.session.commit()
                return {
                    'message': 'success'
                }, 200
            else:
                user.activating_code.last_user_attempt_time = current_time
                db.session.commit()
                raise errors.WrongCodeError()
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()
        except smtplib.SMTPException:
            raise errors.SMTPError()


class RecallPassword(Resource):
    def post(self):
        try:
            data = request.get_json()
            data['email'] = data['email'].lower()
            user = User.query.filter_by(email=data.get('email')).first()
            if user is None:
                raise errors.IncorrectEmailAddressError()
            code_for_password = user.new_password_code
            if code_for_password is not None and code_for_password.creation_date + datetime.timedelta(
                seconds=constants.CONST_NEW_PASSWORD_CODE_REQUEST_INTERVAL
            ) >= datetime.datetime.utcnow():
                raise errors.PRTimeIntervalError()
            code = generate_code(constants.CONST_NEW_PASSWORD_CODE_LENGTH)
            user.new_password_code = NewPasswordCode(
                bcrypt.generate_password_hash(code.encode('utf8')).decode('utf8')
            )
            msg = generate_message('template_for_recalling_password.html',
                                   {'user_name': user.first_name, 'code': code},
                                   [user.email]
                                   )
            mail.send(msg)
            db.session.commit()
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()
        except SMTPException:
            raise errors.SMTPError()

    def put(self):
        try:
            data = request.get_json()
            data['email'] = data['email'].lower()
            user = User.query.filter_by(email=data.get('email')).first()
            current_time = datetime.datetime.utcnow()
            if current_time > user.new_password_code.expiration_date:
                raise errors.CodeExpiredError()
            last_attempt_time = user.new_password_code.last_user_attempt_time
            if last_attempt_time is not None and last_attempt_time + datetime.timedelta(
                seconds=constants.CONST_NEW_PASSWORD_CODE_CHECK_INTERVAL
            ) > current_time:
                raise errors.PCTimeIntervalError()
            if bcrypt.check_password_hash(user.new_password_code.code, data.get('code').encode('utf8')):
                return {
                    'message': 'success'
                }, 200
            else:
                user.new_password_code.last_user_attempt_time = current_time
                db.session.commit()
                raise errors.WrongCodeError()
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()
        except smtplib.SMTPException:
            raise errors.SMTPError()


class PasswordChanger(Resource):
    def put(self):
        try:
            data = request.get_json()
            data['email'] = data['email'].lower()
            user = User.query.filter_by(email=data.get('email')).first()
            if user.new_password_code is None or not bcrypt.check_password_hash(user.new_password_code.code, data.get('code').encode('utf8')):
                raise errors.PermissionDeniedError()
            user.password = bcrypt.generate_password_hash(data.get('password').encode('utf8')).decode('utf8')
            del user.new_password_code
            db.session.commit()
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class AuthenticationCheck(Resource):
    method_decorators = [session_token_check]

    def get(*args, **kwargs):
        return {
            'message': 'success',
            'accountActivated': args[len(args) - 1].confirmed
        }, 200

# file as string in base64
def problem_file_processing(file, file_mime_type):
    try:
        file_data = base64.b64decode(file)
        latex_check = file_mime_type in constants.CONST_TEX_MIME_TYPE
        file_name = 'files/' + str(uuid.uuid4())
        if latex_check:
            tex_file_path = '../' + file_name + '.tex'
            open(tex_file_path, 'wb').write(file_data)
            subprocess.check_call(['pdflatex', '-output-directory', '../files', tex_file_path])
            os.remove(tex_file_path)
            os.remove('../' + file_name + '.aux')
            os.remove('../' + file_name + '.log')
            file_path = file_name + '.pdf'
        else:
            file_path = file_name + '.pdf'
            open('../' + file_path, 'wb').write(file_data)
        return file_path
    except subprocess.CalledProcessError:
        os.remove(tex_file_path)
        os.remove('../' + file_name + '.aux')
        os.remove('../' + file_name + '.log')
        raise errors.TexConversionError()


class AddProblemAPI(Resource):
    method_decorators = [csrf_token_check]

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            if not role_check(user, 'Учитель'):
                raise errors.PermissionDeniedError()
            file_url = problem_file_processing(data.get('file'), data.get('fileMIMEType'))
            data['author'] = user
            data['problemFileURL'] = file_url
            data['status'] = ProblemStatus.query.filter_by(title='Проверяется').first()
            problem = Problem(data)
            user.problems.append(problem)
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()


class ProblemEditingAPI(Resource):
    method_decorators = [csrf_token_check]

    def put(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            problem_id = data.get('problemID')
            if problem_id is None:
                raise errors.IncorrectRequestError()
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            if problem.problem_status == 'Заблокирована':
                raise errors.PermissionDeniedError()
            if user.id != problem.author_id:
                raise errors.PermissionDeniedError()
            files_for_deleting = []
            for session in problem.sessions:
                for attempt in session.attempts:
                    files_for_deleting.append('../' + attempt.student_attempt.file_url)
                    for image in attempt.student_attempt.images:
                        db.session.delete(image)
                        files_for_deleting.append('../' + image.path)
                    if attempt.teacher_feedback is not None:
                        files_for_deleting.append('../' + attempt.teacher_feedback.file_url)
                db.session.delete(session)
            files_for_deleting.append('../' + problem.problem_file_URL)
            db.session.delete(problem)
            db.session.commit()
            for file in files_for_deleting:
                os.remove(file)
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def patch(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            if not role_check(user, 'Учитель'):
                raise errors.PermissionDeniedError()
            problem_id = data.get('problemID')
            new_start_date = data.get('newStartDate')
            new_end_date = data.get('newEndDate')
            new_commentary = data.get('newCommentary')
            if problem_id is None or new_start_date is None or new_end_date is None or new_commentary is None:
                raise errors.IncorrectRequestError()
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            if not problem.can_be_modified():
                raise errors.PermissionDeniedError()
            problem.start_date_of_making_decision = new_start_date
            problem.end_date_of_making_decision = new_end_date
            problem.author_commentary = new_commentary
            db.session.commit()
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()



USER_FIELD = ['authorFullName', 'authorGroup', 'authorLastname', 'authorFirstname']
COMPLEXITY_FIELD = ['problemComplexity']


GP_FILTER_QUERIES = {
    'problemTitle': lambda q, v: q.filter(Problem.title.ilike(v)),
    'authorFullName': lambda q, v: q.filter(
        (User.last_name + ' ' + User.first_name + ' ' + User.middle_name).ilike(v)
    ),
    'authorGroup': lambda q, v: q.filter(User.university_group.ilike(v)),
    'problemDiscipline': lambda q, v: q.filter(Problem.discipline.ilike(v)),
    'problemComplexity': lambda q, v: q.filter(ProblemComplexity.title.ilike(v))
}

GP_ATTRIBUTE_MAPPING = {
    'problemTitle': lambda: Problem.title,
    'authorGroup': lambda: User.university_group,
    'authorFullName': lambda: User.last_name + ' ' + User.first_name + ' ' + User.middle_name,
    'problemDiscipline': lambda: Problem.discipline,
    'problemComplexity': lambda: ProblemComplexity.title
}

SORT_DIRECTIONS = {
    'asc': lambda v: v.asc(),
    'desc': lambda v: v.desc()
}


def gp_request_from_db(inf):
    current_page = inf.get('currentPage')
    page_size = inf.get('pageSize')
    filter_field = inf.get('filterField')
    sort_field = inf.get('sortField')
    sort_dir = inf.get('sortDirection')
    filter_value = inf.get('filterValue')
    if filter_field is None or filter_field not in GP_FILTER_QUERIES.keys():
        raise errors.IncorrectRequestError()
    if sort_field is None or sort_field not in GP_ATTRIBUTE_MAPPING.keys():
        raise errors.IncorrectRequestError()
    if current_page is None or page_size is None or filter_value is None:
        raise errors.IncorrectRequestError()
    if sort_dir is None or sort_dir not in SORT_DIRECTIONS:
        raise errors.IncorrectRequestError()
    current_page = int(current_page)
    page_size = int(page_size)
    current_time = datetime.datetime.utcnow()
    status = ProblemStatus.query.filter_by(title='Принята').first()
    problem_query = Problem.query.filter_by(problem_status_id=status.id)
    problem_query = problem_query.filter(and_(Problem.start_date_of_making_decision < current_time, Problem.end_date_of_making_decision > current_time))
    filter_v = '{}%'.format(filter_value)
    if filter_field in USER_FIELD or sort_field in USER_FIELD:
        problem_query = problem_query.join(User)
    if filter_field in COMPLEXITY_FIELD or sort_field in COMPLEXITY_FIELD:
        problem_query = problem_query.join(ProblemComplexity)
    problem_query = GP_FILTER_QUERIES[filter_field](problem_query, filter_v)
    problem_query = problem_query.order_by(SORT_DIRECTIONS[sort_dir](GP_ATTRIBUTE_MAPPING[sort_field]()), Problem.id.asc())
    problem_count = problem_query.count()
    problem_query = problem_query.offset(page_size * (current_page - 1)).limit(page_size).all()
    return problem_query, problem_count


AS_STUDENT_FILTER_QUERIES = {
    'problemTitle': lambda q, v: q.join(Problem).filter(Problem.title.ilike(v + '%')),
    'authorFullName': lambda q, v: q.join(Problem).join(User).filter(
        (User.last_name + ' ' + User.first_name + ' ' + User.middle_name).ilike(v + '%')
    ),
    'authorGroup': lambda q, v: q.join(Problem).join(User).filter(User.university_group.ilike(v + '%')),
    'problemDiscipline': lambda q, v: q.join(Problem).filter(Problem.discipline.ilike(v + '%'))
}


def as_student_request_from_db(inf, uid):
    current_page = inf.get('currentPage')
    page_size = inf.get('pageSize')
    filter_field = inf.get('filterField')
    filter_value = inf.get('filterValue')
    if filter_field is None or filter_field != '' and filter_field not in AS_STUDENT_FILTER_QUERIES.keys() or filter_field == '':
        raise errors.IncorrectRequestError()
    if current_page is None or page_size is None or filter_value is None:
        raise errors.IncorrectRequestError()
    current_page = int(current_page)
    page_size = int(page_size)
    query = Session.query.filter_by(student_id=uid)
    query = AS_STUDENT_FILTER_QUERIES[filter_field](query, filter_value)
    query = query.order_by(Session.id.asc())
    problems_count = query.count()
    problems = query.offset(page_size * (current_page - 1)).limit(page_size).all()
    return problems, problems_count


AS_TEACHER_FILTER_QUERIES = {
    'problemTitle': lambda v, uid: Problem.query.filter(and_(Problem.author_id == uid, Problem.title.ilike(v + '%'))),
    'problemStatus': lambda v, uid: Problem.query.join(ProblemStatus).filter(and_(ProblemStatus.title.ilike(v + '%'), Problem.author_id == uid))
}

def as_teacher_request_from_db(inf, uid):
    current_page = inf.get('currentPage')
    page_size = inf.get('pageSize')
    filter_field = inf.get('filterField')
    filter_value = inf.get('filterValue')
    if filter_field is None or filter_field != '' and filter_field not in AS_TEACHER_FILTER_QUERIES.keys() or filter_field == '':
        raise errors.IncorrectRequestError()
    if current_page is None or page_size is None or filter_value is None:
        raise errors.IncorrectRequestError()
    current_page = int(current_page)
    page_size = int(page_size)
    query = AS_TEACHER_FILTER_QUERIES[filter_field](filter_value, uid)
    query = query.order_by(Problem.unchecked_attempt_count.desc(), Problem.id.asc())
    problem_count = query.count()
    problems = query.offset(page_size * (current_page - 1)).limit(page_size).all()
    return problems, problem_count


""" 
    Для запроса всех задач пользователя как учителя
    Страница: /my/tasks 
"""

class AsTeacherGetProblemAPI(Resource):
    method_decorators = {
        'post': [session_token_check]
    }

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            data = request.get_json()
            problems, problem_count = as_teacher_request_from_db(data, user.id)
            response_array = []
            for problem in problems:
                response_array.append({
                    'problemID': problem.id,
                    'problemTitle': problem.title,
                    'startDate': date_to_str(problem.start_date_of_making_decision),
                    'endDate': date_to_str(problem.end_date_of_making_decision),
                    'problemStatus': problem.problem_status.title,
                    'haveNewContent': problem.unchecked_attempt_count
                })
            print(problems, problem_count)
            return {
                'message': 'success',
                'problems': response_array,
                'problemCount': problem_count
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


""" 
    Для запроса всех задач пользователя как ученика
    Страница: /my/tasks 
"""

class AsStudentGetProblemsAPI(Resource):
    method_decorators = {
        'post': [session_token_check]
    }

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            data = request.get_json()
            sessions, session_count = as_student_request_from_db(data, user.id)
            response_array = []
            for session in sessions:
                response_array.append({
                    'problemID': session.problem.id,
                    'problemTitle': session.problem.title,
                    'authorFullName': session.problem.author.full_name_with_dots(),
                    'authorGroup': session.problem.author.university_group,
                    'problemDiscipline': session.problem.discipline,
                    'haveNewContent': session.has_new_content_for_student()
                })
            return {
                'message': 'success',
                'problems': response_array,
                'problemCount': session_count
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class GeneralProblemAPI(Resource):
    method_decorators = {
        'post': [session_token_check],
        'get': [session_token_check]
    }

    def post(*args, **kwargs):
        try:
            problem_id = kwargs.get('problem_id')
            if problem_id is None:
                raise errors.IncorrectRequestError()
            if problem_id == '-1':
                args = request.get_json()
                problems, problem_count = gp_request_from_db(args)
                response_array = []
                for problem in problems:
                    response_array.append(
                        {
                            'problemID': problem.id,
                            'problemTitle': problem.title,
                            'authorGroup': problem.author.university_group,
                            'authorFullName': problem.author.full_name_with_dots(),
                            'problemDiscipline': problem.discipline,
                            'problemComplexity': problem.problem_complexity.title
                        }
                    )
                return {
                    'message': 'success',
                    'problems': response_array,
                    'problemCount': problem_count
                }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()

    def get(*args, **kwargs):
        try:
            problem_id = kwargs.get('problem_id')
            user_id = args[len(args) - 1].id
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            if user_id == problem.author_id:
                user_role_in_task = 'Учитель'
            else:
                session = Session.query.filter_by(problem_id=problem_id, student_id=user_id).first()
                if session is None:
                    user_role_in_task = 'Нет'
                else:
                    user_role_in_task = 'Ученик'
            data = {
                'userStatus': user_role_in_task,
                'problemStatus': problem.problem_status.title,
                'problemRejectionReason': problem.rejection_reason if user_role_in_task == 'Учитель' else '',
                'authorFullName': problem.author.full_name(),
                'authorGroup': problem.author.university_group,
                'authorAvatarPath': problem.author.avatar_url,
                'authorCommentary': problem.author_commentary,
                'problemID': problem.id,
                'problemTitle': problem.title,
                'problemDiscipline': problem.discipline,
                'problemComplexity': problem.problem_complexity.title if problem.problem_complexity is not None else '',
                'problemStartLine': date_to_str(problem.start_date_of_making_decision),
                'problemDeadline': date_to_str(problem.end_date_of_making_decision),
                'problemPath': problem.problem_file_URL
            }
            return {
                'message': 'success',
                'data': data
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class SessionAPI(Resource):
    method_decorators = {
        'get': [session_token_check]
    }

    def get(*args, **kwargs):
        try:
            request_get_args = request.args
            user = args[len(args) - 1]
            problem_id = kwargs.get('problem_id')
            filter_value = request_get_args.get('filterValue')
            if problem_id is None or filter_value is None:
                raise errors.IncorrectRequestError()
            sessions = Session.query.filter_by(problem_id=problem_id)
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            if problem.author_id != user.id:
                raise errors.PermissionDeniedError()
            sessions = sessions.join(User)
            if len(filter_value) >= 3 and filter_value[0:2] == '.g':
                sessions = sessions.filter(
                    User.university_group.ilike('{}%'.format(filter_value[2:]))
                )
            else:
                sessions = sessions.filter(
                    (User.last_name + ' ' + User.first_name + ' ' + User.middle_name).ilike('{}%'.format(filter_value))
                )
            session_count = sessions.count()
            sessions = sessions.order_by(Session.unchecked_attempt_count.desc(), Session.id.asc())
            response_data_array = []
            for session in sessions:
                response_data_array.append(
                    {
                        'sessionID': session.id,
                        'studentFullName': session.student.full_name(),
                        'studentGroup': session.student.university_group,
                        'studentAvatarPath': session.student.avatar_url,
                        'unverifiedAttemptCount': session.unchecked_attempt_count,
                        'sessionHasNewCommentariesForTeacher': session.has_new_commentary_for_teacher > 0
                    }
                )
            return {
                'message': 'success',
                'sessionInfo': response_data_array,
                'sessionCount': session_count
            }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()

class AttemptEditingAPI(Resource):
    method_decorators = {
        'post': [csrf_token_check],
        'put': [csrf_token_check]
    }

    def put(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            attempt_id = data.get('attemptID')
            if attempt_id is None:
                raise errors.IncorrectRequestError()
            attempt = Attempt.query.filter_by(id=attempt_id).first()
            if attempt is None:
                raise errors.AttemptNotFoundError()
            if attempt.session.student_id != user.id:
                raise errors.PermissionDeniedError()
            if attempt.session.problem.problem_status.title == 'Заблокирована':
                raise errors.PermissionDeniedError()
            file_urls = [attempt.student_attempt.file_url]
            for image in attempt.student_attempt.images:
                file_urls.append(image.path)
            if attempt.teacher_feedback is not None:
                file_urls.append(attempt.teacher_feedback.file_url)
            if len(attempt.session.attempts) == 1:
                db.session.delete(attempt.session)
            db.session.delete(attempt)
            db.session.commit()
            for path in file_urls:
                os.remove('../' + path)
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            problem_id = data.get('problemID')
            if problem_id is None:
                raise errors.IncorrectRequestError()
            if not role_check(user, 'Ученик'):
                raise errors.PermissionDeniedError()
            file = data.get('file')
            file_mime_type = data.get('fileMIMEType')
            if file is None or file_mime_type is None:
                raise errors.IncorrectRequestError()
            file_url = problem_file_processing(file, file_mime_type)
            session = Session.query.filter_by(student_id=user.id, problem_id=problem_id).first()
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            if not problem.can_be_modified():
                raise errors.PermissionDeniedError()
            if session is None:
                current_time = datetime.datetime.utcnow()
                if problem.start_date_of_making_decision > current_time or problem.end_date_of_making_decision < current_time:
                    raise errors.AttemptCanNotBeAdded()
                student_attempt = StudentAttempt(file_url)
                session_status = SessionStatus.query.filter_by(title='Открыта').first()
                new_session = Session(session_status, student_attempt, user, problem)
                user.sessions.append(new_session)
                problem.sessions.append(new_session)
            else:
                if session.status.title != 'Открыта':
                    raise errors.PermissionDeniedError()
                student_attempt = StudentAttempt(file_url)
                session.add_attempt(student_attempt)
            db.session.flush()
            response_data = {
                'message': 'success',
                'attempt': student_attempt.for_transmitting()
            }
            db.session.commit()
            return response_data, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            os.remove('../' + file_url)
            raise errors.DatabaseError()


PA_FILTER_QUERIES = {
    'problemTitle': lambda q, v: q.filter(Problem.title.ilike(v)),
    'authorLastname': lambda q, v: q.filter(User.last_name.ilike(v)),
    'authorFirstname': lambda q, v: q.filter(User.first_name.ilike(v)),
    'authorGroup': lambda q, v: q.filter(User.university_group.ilike(v))
}


PA_ATTRIBUTE_MAPPING = {
    'problemTitle': lambda: Problem.title,
    'authorLastname': lambda: User.last_name,
    'authorFirstname': lambda: User.first_name,
    'authorGroup': lambda: User.university_group,
    'problemStartLine': lambda: Problem.start_date_of_making_decision,
    'problemDeadline': lambda: Problem.end_date_of_making_decision
}


def pa_request_from_db(inf):
    current_page = inf.get('currentPage')
    page_size = inf.get('pageSize')
    filter_field = inf.get('filterField')
    sort_field = inf.get('sortField')
    sort_dir = inf.get('sortDirection')
    filter_value = inf.get('filterValue')
    if filter_field is None or filter_field not in PA_FILTER_QUERIES.keys():
        raise errors.IncorrectRequestError()
    if sort_field is None or sort_field not in PA_ATTRIBUTE_MAPPING.keys():
        raise errors.IncorrectRequestError()
    if current_page is None or page_size is None or filter_value is None:
        raise errors.IncorrectRequestError()
    if sort_dir is None or sort_dir not in SORT_DIRECTIONS:
        raise errors.IncorrectRequestError()
    current_page = int(current_page)
    page_size = int(page_size)
    current_time = datetime.datetime.utcnow()
    next_try_time = datetime.timedelta(seconds=constants.CONST_PROBLEM_ADMITTING_ATTEMPT_INTERVAL)
    status = ProblemStatus.query.filter_by(title='Проверяется').first()
    problem_query = Problem.query.filter_by(problem_status_id=status.id)
    problem_query = problem_query.filter(or_(
        Problem.last_admitting_attempt == None,
        Problem.last_admitting_attempt + next_try_time <= current_time
    ))
    filter_v = '{}%'.format(filter_value)
    if filter_field in USER_FIELD or sort_field in USER_FIELD:
        problem_query = problem_query.join(User)
    if filter_field in COMPLEXITY_FIELD or sort_field in COMPLEXITY_FIELD:
        problem_query = problem_query.join(ProblemComplexity)
    problem_query = PA_FILTER_QUERIES[filter_field](problem_query, filter_v)
    problem_query = problem_query.order_by(SORT_DIRECTIONS[sort_dir](PA_ATTRIBUTE_MAPPING[sort_field]()), Problem.id.asc())
    problem_count = problem_query.count()
    problem_query = problem_query.offset(page_size * (current_page - 1)).limit(page_size).all()
    return problem_query, problem_count


class ProblemAdmittingAPI(Resource):
    method_decorators = {
        'patch': [csrf_token_check],
        'post': [session_token_check],
        'get': [session_token_check]
    }

    def post(*args, **kwargs):
        try:
            if not role_check(args[len(args) - 1], 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            problem_id = kwargs.get('problem_id')
            if problem_id is None:
                raise errors.IncorrectRequestError()
            args = request.get_json()
            if problem_id == '-1':
                problems, problem_count = pa_request_from_db(args)
                response_array = []
                for problem in problems:
                    response_array.append({
                        'problemID': problem.id,
                        'problemTitle': problem.title,
                        'problemDeadline': date_to_str(problem.end_date_of_making_decision),
                        'problemStartLine': date_to_str(problem.start_date_of_making_decision),
                        'authorGroup': problem.author.university_group,
                        'authorFirstname': problem.author.first_name,
                        'authorLastname': problem.author.last_name
                    })
                return {
                    'message': 'success',
                    'problems': response_array,
                    'problemCount': problem_count
                }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()

    def get(*args, **kwargs):
        try:
            if not role_check(args[len(args) - 1], 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            problem_id = kwargs.get('problem_id')
            if problem_id is None:
                raise errors.IncorrectRequestError()
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            if problem.problem_status.title != 'Проверяется':
                raise errors.ProblemAlreadyAdmittedError()
            if problem.last_admitting_attempt is not None and datetime.datetime.utcnow() - problem.last_admitting_attempt < datetime.timedelta(seconds=constants.CONST_PROBLEM_ADMITTING_ATTEMPT_INTERVAL):
                raise errors.ProblemIsAdmittingNow()
            problem.last_admitting_attempt = datetime.datetime.utcnow()
            data = {
                'authorFullname': problem.author.full_name(),
                'authorGroup': problem.author.university_group,
                'problemTitle': problem.title,
                'problemDiscipline': problem.discipline,
                'problemStartLine': date_to_str(problem.start_date_of_making_decision),
                'problemDeadline': date_to_str(problem.end_date_of_making_decision),
                'authorCommentary': problem.author_commentary,
                'problemURL': problem.problem_file_URL
            }
            db.session.commit()
            return {
                'message': 'success',
                'data': data
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def patch(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            problem_id = kwargs.get('problem_id')
            if problem_id is None:
                raise errors.IncorrectRequestError()
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            if problem.problem_status.title != 'Проверяется':
                raise errors.ProblemAlreadyAdmittedError()
            status_title = data.get('problemStatus')
            if status_title is None:
                raise errors.IncorrectRequestError()
            if status_title == 'Принята' and not role_check(problem.author, 'Учитель'):
                status_title = 'Заблокирована'
            status = ProblemStatus.query.filter_by(title=status_title).first()
            problem.problem_status = status
            if problem.problem_status.title == 'Отклонена':
                rejection_reason = data.get('rejectionReason')
                if rejection_reason is None:
                    raise errors.IncorrectRequestError()
                problem.rejection_reason = rejection_reason
            else:
                problem_complexity_title = data.get('problemComplexity')
                if problem_complexity_title is None:
                    raise errors.IncorrectRequestError()
                problem_complexity = ProblemComplexity.query.filter_by(title=problem_complexity_title).first()
                if problem_complexity is None:
                    raise errors.IncorrectRequestError()
                problem.problem_complexity = problem_complexity
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class RoleCheck(Resource):
    method_decorators = {
        'get': [session_token_check]
    }

    def get(*args, **kwargs):
        request_get_args = request.args
        result = False
        for arg in request_get_args.values():
            result = result or role_check(args[len(args) - 1], arg)
        return {
            'message': 'success',
            'roleCheck': result
        }, 200


class GetAttemptAPI(Resource):
    method_decorators = {
        'post': [session_token_check],
        'get': [session_token_check]
    }

    def get(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            request_args = request.args
            problem_id = request_args.get('problemID')
            session_id = request_args.get('sessionID')
            if problem_id is None or session_id is None:
                raise errors.IncorrectRequestError()
            if session_id == '-1':
                is_teacher = False
                session = Session.query.filter_by(problem_id=problem_id, student_id=user.id).first()
            else:
                is_teacher = True
                session = Session.query.filter_by(id=session_id).first()
            if session is None:
                raise errors.SessionNotFoundError()
            if session.status.title == 'Заблокирована':
                return {
                    'message': 'success',
                    'attempts': [],
                    'sessionStatus': session.status.title
                }
            attempts = []
            for attempt in session.attempts:
                attempts.append({
                    'studentAttempt': attempt.student_attempt.for_transmitting(),
                    'attemptHasNewCommentary': attempt.has_new_commentaries_for_student > 0 if not is_teacher else attempt.has_new_commentaries_for_teacher > 0,
                    'teacherFeedbackStatus': attempt.teacher_feedback.status.title if attempt.teacher_feedback is not None else '',
                })
            return {
                'message': 'success',
                'attempts': attempts,
                'sessionStatus': session.status.title
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def post(*args, **kwargs):
        try:
            data = request.get_json()
            user = args[len(args) - 1]
            attempt_id = data.get('attemptID')
            if attempt_id is None:
                raise errors.IncorrectRequestError()
            attempt = Attempt.query.filter_by(id=attempt_id).first()
            if attempt is None:
                raise errors.AttemptNotFoundError()
            is_teacher = user.id != attempt.session.student_id
            response = {
                'teacherFeedback': attempt.teacher_feedback.for_transmitting(is_teacher) if attempt.teacher_feedback is not None else None,
                'commentaries': []
            }
            for commentary in attempt.commentaries:
                response['commentaries'].append(commentary.for_transmitting())
                if is_teacher is True:
                    commentary.is_new_for_teacher = False
                else:
                    commentary.is_new_for_student = False
            if not is_teacher:
                if attempt.teacher_feedback is not None and attempt.teacher_feedback.status.title == 'Отзыв не просмотрен учеником':
                    attempt.teacher_feedback.status = TeacherFeedbackStatus.query.filter_by(title='Отзыв просмотрен учеником').first()
            response['teacherFeedbackStatus'] = attempt.teacher_feedback.status.title if attempt.teacher_feedback is not None else ''
            db.session.flush()
            if is_teacher is True:
                response['sessionStatus'] = attempt.session.has_new_commentary_for_teacher
            db.session.commit()
            return {
                'message': 'success',
                'attempt': response
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


def create_pdf_from_png(png_array):
    temporary_image = []
    for png in png_array:
        im = Image.open(BytesIO(base64.b64decode(png)))
        temporary_image.append(Image.new('RGB', im.size, (255, 255, 255)))
        temporary_image[len(temporary_image) - 1].paste(im, mask=im.split()[3])
    pdf_path = 'files/' + str(uuid.uuid4()) + '.pdf'
    temporary_image[0].save('../' + pdf_path, 'PDF', resolution=100.0, save_all=True, append_images=temporary_image[1:])
    return pdf_path


class AttemptCheckAPI(Resource):
    method_decorators = {
        'get': [session_token_check],
        'post': [csrf_token_check],
        'put': [csrf_token_check]
    }

    def put(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            attempt_id = data.get('attemptID')
            if attempt_id is None:
                raise errors.IncorrectRequestError()
            attempt = Attempt.query.filter_by(id=attempt_id).first()
            if user.id != attempt.session.problem.author_id:
                raise errors.PermissionDeniedError()
            if attempt.session.problem.problem_status.title == 'Заблокирована':
                raise errors.PermissionDeniedError()
            if attempt.session.status.title == 'Заблокирована':
                raise errors.PermissionDeniedError()
            file_paths = ['../' + attempt.teacher_feedback.file_url]
            if attempt.student_attempt.images is not None:
                for image in attempt.student_attempt.images:
                    file_paths.append('../' + image.path)
                    db.session.delete(image)
            db.session.delete(attempt.teacher_feedback)
            attempt.student_attempt.status = StudentAttemptStatus.query.filter_by(title='Попытка проверяется учителем').first()
            db.session.commit()
            for path in file_paths:
                os.remove(path)
            return {
                'message': 'success',
                'studentAttemptStatus': attempt.student_attempt.status.title
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            attempt_id = kwargs.get('attempt_id')
            if attempt_id is None:
                raise errors.AttemptNotFoundError()
            attempt = Attempt.query.filter_by(id=attempt_id).first()
            if attempt is None:
                raise errors.AttemptNotFoundError()
            if attempt.session.problem.author.id != user.id:
                raise errors.PermissionDeniedError()
            if not attempt.session.problem.can_be_modified() or attempt.session.status.title == 'Заблокирована':
                raise errors.PermissionDeniedError()
            solution_degree_title = data.get('solutionDegree')
            teacher_commentary = data.get('teacherCommentary')
            pages = data.get('pages')
            status = data.get('status')
            if solution_degree_title is None or teacher_commentary is None or pages is None or status is None:
                raise errors.IncorrectRequestError()
            solution_degree = SolutionDegree.query.filter_by(title=solution_degree_title).first()
            if solution_degree is None:
                raise errors.IncorrectRequestError()
            pdf_path = create_pdf_from_png(pages)
            del_image_paths = []
            if attempt.teacher_feedback is not None:
                db.session.delete(attempt.teacher_feedback)
                del_image_paths.append('../' + attempt.teacher_feedback.file_url)
            teacher_feedback_status = TeacherFeedbackStatus.query.filter_by(title=status).first()
            if teacher_feedback_status is None:
                raise errors.IncorrectRequestError()
            if status == 'Отзыв не просмотрен учеником' and attempt.student_attempt.status.title != 'Попытка проверена учителем':
                attempt.student_attempt.status = StudentAttemptStatus.query.filter_by(title='Попытка проверена учителем').first()
            if status == 'Черновик отзыва' and attempt.student_attempt.status.title != 'Попытка проверяется учителем':
                attempt.student_attempt.status = StudentAttemptStatus.query.filter_by(title='Попытка проверяется учителем').first()
            teacher_feedback = TeacherFeedback(solution_degree, teacher_commentary, pdf_path)
            teacher_feedback.status = teacher_feedback_status
            attempt.teacher_feedback = teacher_feedback
            for image in attempt.student_attempt.images:
                del_image_paths.append('../' + image.path)
                db.session.delete(image)
            db.session.commit()
            for path in del_image_paths:
                os.remove(path)
            response_data = {
                'message': 'success'
            }
            return response_data, 201
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()
        except OSError:
            traceback.print_exc()
            raise errors.PDFFromPNGError()

    def get(*args, **kwargs):
        try:
            del_image_paths = []
            user = args[-1]
            attempt_id = kwargs.get('attempt_id')
            print(attempt_id)
            attempt = Attempt.query.filter_by(id=attempt_id).first()
            if attempt is None:
                raise errors.AttemptNotFoundError()
            if attempt.session.problem.author_id != user.id or not role_check(user, 'Учитель'):
                raise errors.PermissionDeniedError()
            student_attempt = attempt.student_attempt
            if student_attempt.images is not None and len(student_attempt.images) != 0:
                for image in student_attempt.images:
                    del_image_paths.append('../' + image.path)
                    db.session.delete(image)
            if attempt.teacher_feedback is not None:
                images = convert_from_path('../' + attempt.teacher_feedback.file_url, size=(794, 1223), dpi=96)
            else:
                images = convert_from_path('../' + student_attempt.file_url, size=(794, 1223), dpi=96)
            paths = []
            for image in images:
                paths.append('files/' + str(uuid.uuid4()) + '.png')
                student_attempt.images.append(ImagePath(paths[len(paths) - 1]))
                image.save('../' + paths[len(paths) - 1])
            response_data = {
                'message': 'success',
                'imagePaths': paths,
                'problemPath': attempt.session.problem.problem_file_URL,
                'authorInf': {
                    'authorFullName': attempt.session.student.full_name(),
                    'authorAvatarPath': attempt.session.student.avatar_url,
                    'authorGroup': attempt.session.student.university_group
                },
                'authorCommentary': '' if attempt.teacher_feedback is None else attempt.teacher_feedback.teacher_commentary,
                'solutionDegree': '' if attempt.teacher_feedback is None else attempt.teacher_feedback.solution_degree.title
            }
            if attempt.student_attempt.status.title != 'Попытка проверяется учителем':
                attempt.student_attempt.status = StudentAttemptStatus.query.filter_by(title='Попытка проверяется учителем').first()
            db.session.commit()
            for path in del_image_paths:
                os.remove(path)
            return response_data, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()


class CommentaryAPI(Resource):
    method_decorators = {
        'post': [csrf_token_check],
        'put': [csrf_token_check]
    }

    def put(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            commentary_id = data.get('commentaryID')
            if commentary_id is None:
                raise errors.IncorrectRequestError()
            commentary_id = int(commentary_id)
            commentary = Commentary.query.filter_by(id=commentary_id).first()
            if commentary is None:
                raise errors.CommentaryNotFoundError()
            if commentary.author_id != user.id:
                raise errors.PermissionDeniedError()
            if commentary.attempt.session.problem.problem_status.title == 'Заблокирована':
                raise errors.PermissionDeniedError()
            if commentary.attempt.session.status.title == 'Заблокирована':
                raise errors.PermissionDeniedError()
            db.session.delete(commentary)
            db.session.commit()
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            attempt_id = data.get('attemptID')
            if attempt_id is None:
                raise errors.IncorrectRequestError()
            attempt = Attempt.query.filter_by(id=attempt_id).first()
            if attempt is None:
                raise errors.AttemptNotFoundError()
            if not attempt.session.problem.can_be_modified():
                raise errors.PermissionDeniedError()
            if attempt.session.status.title == 'Заблокирована':
                raise errors.PermissionDeniedError()
            student_id = attempt.session.student_id
            author_id = attempt.session.problem.author_id
            if user.id != student_id and user.id != author_id and attempt.student_attempt.attempt_number != attempt.session.current_attempt:
                raise errors.PermissionDeniedError()
            new_commentary = Commentary(data.get('commentaryText'), user.id == author_id)
            user.commentaries.append(new_commentary)
            attempt.commentaries.append(new_commentary)
            db.session.flush()
            commentary_id = new_commentary.id
            commentary_time = date_to_str(new_commentary.commentary_time)
            db.session.commit()
            return {
                'message': 'success',
                'commentaryID': commentary_id,
                'commentaryTime': commentary_time
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class HideStatusAPI(Resource):
    method_decorators = {
        'patch': [csrf_token_check]
    }

    def patch(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            problem_id = data.get('problemID')
            new_status_title = data.get('newStatusTitle')
            if problem_id is None or new_status_title is None:
                raise errors.IncorrectRequestError()
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            if problem.author_id != user.id:
                raise errors.PermissionDeniedError()
            if problem.problem_status.title != 'Принята' and problem.problem_status.title != 'Скрыта':
                raise errors.PermissionDeniedError()
            new_status = ProblemStatus.query.filter_by(title=new_status_title).first()
            if new_status is None:
                raise errors.IncorrectRequestError()
            problem.problem_status = new_status
            if new_status_title == 'Принята':
                problem.is_hide = False
            else:
                problem.is_hide = True
            db.session.commit()
            return {
                'message': 'success',
                'newStatus': problem.problem_status.title
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


"""
    Администрирование
    Администраторские роли: Администратор, Помощник администратора
    Удалять администраторы могут любые комментарии, текущую попытку каждой сессии и саму задачу
    Одновременно у пользователя может быть только одна администраторская роль
    При блокировании учительской роли только задачи со статусами "Принята" и "Скрыта"
    меняют статус на "Заблокирована". Задачи, которые остались на рассмотрении, получат статус этот статус,
    если будут допущены администратором.
"""


class AdminGetUser(Resource):
    method_decorators = {
        'post': [session_token_check]
    }

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            data = request.get_json()
            filter_value = data.get('filterValue')
            filter_field = data.get('filterField')
            current_page = data.get('currentPage')
            page_size = data.get('pageSize')
            if filter_field is None or filter_value is None or current_page is None or page_size is None:
                raise errors.IncorrectRequestError()
            if filter_field == 'userFullName':
                users = User.query.filter((User.last_name + ' ' + User.first_name + ' ' + User.middle_name).ilike(filter_value + '%'))
            else:
                users = User.query.filter(User.university_group.ilike(filter_value + '%'))
            users = users.order_by(User.id.asc())
            user_count = users.count()
            users = users.offset(page_size * (current_page - 1)).limit(page_size).all()
            response_data = []
            for user in users:
                response_data.append({
                    'userID': user.id,
                    'userFullName': user.full_name(),
                    'userGroup': user.university_group,
                    'studentRole': any(role.title == 'Ученик' for role in user.roles),
                    'teacherRole': any(role.title == 'Учитель' for role in user.roles),
                    'adminRole': any(role.title == 'Администратор' for role in user.roles),
                    'subAdminRole': any(role.title == 'Помощник администратора' for role in user.roles),
                })
            return {
                'message': 'success',
                'data': response_data,
                'count': user_count
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class AdminGetProblem(Resource):
    method_decorators = {
        'post': [session_token_check]
    }

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.IncorrectRequestError()
            data = request.get_json()
            filter_value = data.get('filterValue')
            filter_field = data.get('filterField')
            current_page = data.get('currentPage')
            page_size = data.get('pageSize')
            if filter_field is None or filter_value is None or current_page is None or page_size is None:
                raise errors.IncorrectRequestError()
            problems = Problem.query
            if filter_field == 'problemTitle':
                problems = problems.filter(Problem.title.ilike(filter_value + '%'))
            if filter_field == 'authorFullName':
                problems = problems.join(User).filter((User.last_name + ' ' + User.first_name + ' ' + User.middle_name).ilike(filter_value + '%'))
            if filter_field == 'authorGroup':
                problems = problems.join(User).filter(User.university_group.ilike(filter_value + '%'))
            if filter_field == 'problemDiscipline':
                problems = problems.filter(Problem.discipline.ilike(filter_value + '%'))
            problems = problems.order_by(Problem.id.asc())
            problem_count = problems.count()
            problems = problems.offset(page_size * (current_page - 1)).limit(page_size).all()
            response_array = []
            for problem in problems:
                response_array.append({
                    'problemID': problem.id,
                    'problemTitle': problem.title,
                    'authorFullName': problem.author.full_name_with_dots(),
                    'authorGroup': problem.author.university_group,
                    'problemDiscipline': problem.discipline
                })
            return {
                'message': 'success',
                'data': response_array,
                'count': problem_count
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


def up_student(user):
    role = Role.query.filter_by(title='Ученик').first()
    if role_check(user, 'Ученик'):
        raise errors.IncorrectRequestError()
    open_status = SessionStatus.query.filter_by(title='Открыта').first()
    for session in user.sessions:
        session.status = open_status
    user.roles.append(role)

def down_student(user, raise_exception_flag=True):
    role = Role.query.filter_by(title='Ученик').first()
    if not role_check(user, 'Ученик'):
        if not raise_exception_flag:
            return
        raise errors.IncorrectRequestError()
    block_status = SessionStatus.query.filter_by(title='Заблокирована').first()
    for session in user.sessions:
        session.status = block_status
    user.roles.remove(role)

def up_teacher(user):
    role = Role.query.filter_by(title='Учитель').first()
    if role_check(user, 'Учитель'):
        raise errors.IncorrectRequestError()
    open_status = ProblemStatus.query.filter_by(title='Принята').first()
    hide_status = ProblemStatus.query.filter_by(title='Скрыта').first()
    for problem in user.problems:
        if problem.problem_status.title == 'Заблокирована':
            if problem.is_hide:
                problem.problem_status = hide_status
            else:
                problem.problem_status = open_status
    user.roles.append(role)

def down_teacher(user, raise_exception_flag=True):
    role = Role.query.filter_by(title='Учитель').first()
    if not role_check(user, 'Учитель'):
        if not raise_exception_flag:
            return
        raise errors.IncorrectRequestError()
    block_status = ProblemStatus.query.filter_by(title='Заблокирована').first()
    for problem in user.problems:
        if problem.problem_status.title == 'Принята' or problem.problem_status.title == 'Скрыта':
            problem.problem_status = block_status
    user.roles.remove(role)

def up_sub_admin(user):
    role = Role.query.filter_by(title='Помощник администратора').first()
    if role_check(user, 'Помощник администратора'):
        raise errors.IncorrectRequestError()
    user.roles.append(role)

def down_sub_admin(user):
    role = Role.query.filter_by(title='Помощник администратора').first()
    if not role_check(user, 'Помощник администратора'):
        raise errors.IncorrectRequestError()
    user.roles.remove(role)

ROLE_CHANGER = {
    'up': {
        'Ученик': up_student,
        'Учитель': up_teacher,
        'Помощник администратора': up_sub_admin
    },
    'down': {
        'Ученик': down_student,
        'Учитель': down_teacher,
        'Помощник администратора': down_sub_admin
    }
}

class AdminChangeRole(Resource):
    method_decorators = {
        'patch': [session_token_check]
    }
    def patch(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            data = request.get_json()
            role_title = data.get('roleTitle')
            mode = data.get('mode')
            target_id = data.get('targetID')
            if role_title is None or mode is None or target_id is None:
                raise errors.IncorrectRequestError()
            if role_title == 'Администратор':
                raise errors.PermissionDeniedError()
            if role_title == 'Помощник администратора' and role_check(user, 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            target = User.query.filter_by(id=target_id).first()
            if target is None:
                raise errors.UserNotFound()
            "Либо админ, либо его помощник. Сразу двумя пользователь быть не может"
            if role_check(target, 'Администратор') and role_title == 'Помощник администратора':
                raise errors.IncorrectRequestError()
            if mode not in ROLE_CHANGER or role_title not in ROLE_CHANGER[mode]:
                raise errors.IncorrectRequestError()
            ROLE_CHANGER[mode][role_title](target)
            db.session.commit()
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

def get_teacher_statistic_by_user(user_id, start_date, end_date):
    all_problem_count = Problem.query.filter(
        and_(Problem.author_id == user_id,
             Problem.creation_date >= start_date,
             Problem.creation_date <= end_date)
    ).count()
    accepted_problem_count = Problem.query.join(ProblemStatus).filter(
        and_(Problem.author_id == user_id,
             Problem.creation_date >= start_date,
             Problem.creation_date <= end_date,
             ProblemStatus.title != 'Проверяется',
             ProblemStatus.title != 'Отклонена'
             )
    ).count()
    simple_problem_count = Problem.query.join(ProblemStatus).join(ProblemComplexity).filter(
        and_(Problem.author_id == user_id,
             Problem.creation_date >= start_date,
             Problem.creation_date <= end_date,
             ProblemStatus.title != 'Проверяется',
             ProblemStatus.title != 'Отклонена',
             ProblemComplexity.title == 'Простая'
             )
    ).count()
    average_problem_count = Problem.query.join(ProblemStatus).join(ProblemComplexity).filter(
        and_(Problem.author_id == user_id,
             Problem.creation_date >= start_date,
             Problem.creation_date <= end_date,
             ProblemStatus.title != 'Проверяется',
             ProblemStatus.title != 'Отклонена',
             ProblemComplexity.title == 'Средняя'
             )
    ).count()
    difficult_problem_count = Problem.query.join(ProblemStatus).join(ProblemComplexity).filter(
        and_(Problem.author_id == user_id,
             Problem.creation_date >= start_date,
             Problem.creation_date <= end_date,
             ProblemStatus.title != 'Проверяется',
             ProblemStatus.title != 'Отклонена',
             ProblemComplexity.title == 'Сложная'
             )
    ).count()
    average_complexity = 1 * simple_problem_count + 2 * average_problem_count + 3 * difficult_problem_count
    if average_complexity != 0:
        average_complexity /= simple_problem_count + average_problem_count + difficult_problem_count
    checked_attempt_count = TeacherFeedback.query.join(Attempt).join(Session).join(Problem).filter(
        and_(TeacherFeedback.creation_time >= start_date,
             TeacherFeedback.creation_time <= end_date,
             Problem.author_id == user_id
             )
    ).count()
    absolutely_solved_attempt = TeacherFeedback.query.join(Attempt).join(SolutionDegree).join(Session).join(Problem).filter(
        and_(TeacherFeedback.creation_time >= start_date,
             TeacherFeedback.creation_time <= end_date,
             SolutionDegree.title == 'Полностью решена',
             Problem.author_id == user_id
             )
    ).count()
    return {
        'allProblemCount': all_problem_count,
        'acceptedProblemCount': accepted_problem_count,
        'averageDifficultOfProblems': average_complexity,
        'attemptCheckCount': checked_attempt_count,
        'absolutelySolvedAttemptCount': absolutely_solved_attempt
    }

def get_student_statistic_by_user(user_id, start_date, end_date):
    absolutely_solved_attempt_count = StudentAttempt.query.join(Attempt).join(Session).join(TeacherFeedback).join(SolutionDegree).filter(
        and_(StudentAttempt.creation_time >= start_date,
             StudentAttempt.creation_time <= end_date,
             SolutionDegree.title == 'Полностью решена',
             Session.student_id == user_id)
    ).count()
    almost_solved_attempt_count = StudentAttempt.query.join(Attempt).join(Session).join(TeacherFeedback).join(SolutionDegree).filter(
        and_(StudentAttempt.creation_time >= start_date,
             StudentAttempt.creation_time <= end_date,
             SolutionDegree.title == 'Почти решена',
             Session.student_id == user_id)
    ).count()
    right_idea_attempt_count = StudentAttempt.query.join(Attempt).join(Session).join(TeacherFeedback).join(SolutionDegree).filter(
        and_(StudentAttempt.creation_time >= start_date,
             StudentAttempt.creation_time <= end_date,
             SolutionDegree.title == 'Есть идея',
             Session.student_id == user_id)
    ).count()
    simple_problem_count = StudentAttempt.query.join(Attempt).join(Session).join(Problem).join(ProblemComplexity).filter(
        and_(StudentAttempt.creation_time >= start_date,
             StudentAttempt.creation_time <= end_date,
             Session.student_id == user_id,
             ProblemComplexity.title == 'Простая')
    ).count()
    average_problem_count = StudentAttempt.query.join(Attempt).join(Session).join(Problem).join(ProblemComplexity).filter(
        and_(StudentAttempt.creation_time >= start_date,
             StudentAttempt.creation_time <= end_date,
             Session.student_id == user_id,
             ProblemComplexity.title == 'Средняя')
    ).count()
    difficult_problem_count = StudentAttempt.query.join(Attempt).join(Session).join(Problem).join(ProblemComplexity).filter(
        and_(StudentAttempt.creation_time >= start_date,
             StudentAttempt.creation_time <= end_date,
             Session.student_id == user_id,
             ProblemComplexity.title == 'Сложная')
    ).count()
    average_complexity = 1 * simple_problem_count + 2 * average_problem_count + 3 * difficult_problem_count
    if average_complexity != 0:
        average_complexity /= simple_problem_count + average_problem_count + difficult_problem_count
    return {
        'absolutelySolvedAttemptCount': absolutely_solved_attempt_count,
        'almostSolvedAttemptCount': almost_solved_attempt_count,
        'haveRightIdeaAttemptCount': right_idea_attempt_count,
        'averageDifficultOfProblems': average_complexity
    }

def get_statistic_by_problem(problem_id, start_date, end_date):
    response_object = {
        'Полностью решена': 0,
        'Почти решена': 0,
        'Есть идея': 0,
        'Пока не решена': 0
    }
    feedbacks = TeacherFeedback.query.join(Attempt).join(Session).join(Problem).filter(
        and_(Problem.id == problem_id,
             TeacherFeedback.creation_time >= start_date,
             TeacherFeedback.creation_time <= end_date
             )
    ).all()
    for feedback in feedbacks:
        response_object[feedback.solution_degree.title] += 1
    return {
        'absolutelySolvedPeopleCount': response_object['Полностью решена'],
        'almostSolvedPeopleCount': response_object['Почти решена'],
        'haveRightIdeaPeopleCount': response_object['Есть идея'],
        'haveWrongIdeaPeopleCount': response_object['Пока не решена']
    }

class AdminStatistic(Resource):
    method_decorators = {
        'post': [session_token_check]
    }

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            data = request.get_json()
            mode = data.get('mode')
            target_id = data.get('id')
            start_date = data.get('startDate')
            end_date = data.get('endDate')
            if mode is None or target_id is None or start_date is None or end_date is None:
                raise errors.IncorrectRequestError()
            start_date = datetime.datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%S.%fZ")
            end_date = datetime.datetime.strptime(end_date, "%Y-%m-%dT%H:%M:%S.%fZ")
            if mode == 'problem':
                response = get_statistic_by_problem(target_id, start_date, end_date)
            else:
                response = {
                    'teacherStatistic': get_teacher_statistic_by_user(target_id, start_date, end_date),
                    'studentStatistic': get_student_statistic_by_user(target_id, start_date, end_date)
                }
            return {
                'message': 'success',
                'data': response
            }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()


class AdminGetAllSessionsByStudent(Resource):
    method_decorators = {
        'post': [session_token_check],
        'get': [session_token_check]
    }

    def get(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            target_id = kwargs.get('user_id')
            target = User.query.filter_by(id=target_id).first()
            if target is None:
                raise errors.UserNotFound()
            return {
                'message': 'success',
                'data': {
                    'avatarPath': target.avatar_url,
                    'fullName': target.full_name(),
                    'group': target.university_group
                }
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            data = request.get_json()
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            target_id = int(kwargs.get('user_id'))
            target = User.query.filter_by(id=target_id).first()
            if target is None:
                raise errors.UserNotFound()
            sessions, session_count = as_student_request_from_db(data, target_id)
            response_data = []
            for session in sessions:
                response_data.append({
                    'sessionID': session.id,
                    'problemID': session.problem_id,
                    'problemTitle': session.problem.title,
                    'authorFullName': session.problem.author.full_name_with_dots(),
                    'authorGroup': session.problem.author.university_group,
                    'problemDiscipline': session.problem.discipline
                })
            return {
                'message': 'success',
                'data': response_data,
                'count': session_count
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class AdminGetAllProblemsByTeacher(Resource):
    method_decorators = {
        'post': [session_token_check]
    }

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            target_id = int(kwargs.get('user_id'))
            target = User.query.filter_by(id=target_id).first()
            if target is None:
                raise errors.UserNotFound()
            data = request.get_json()
            problems, problem_count = as_teacher_request_from_db(data, target_id)
            response_array = []
            for problem in problems:
                response_array.append({
                    'problemID': problem.id,
                    'problemTitle': problem.title,
                    'startDate': date_to_str(problem.start_date_of_making_decision),
                    'endDate': date_to_str(problem.end_date_of_making_decision),
                    'problemStatus': problem.problem_status.title
                })
            return {
                'message': 'success',
                'data': response_array,
                'count': problem_count
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


SORT_FIELDS = {
    'studentFullName': lambda: User.last_name + ' ' + User.first_name + ' ' + User.middle_name,
    'studentGroup': lambda: User.university_group
}

class AdminGetSessionsByProblem(Resource):
    method_decorators = {
        'get': [session_token_check]
    }

    def get(*args, **kwargs):
        try:
            request_get_args = request.args
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            problem_id = kwargs.get('problem_id')
            filter_value = request_get_args.get('filterValue')
            if problem_id is None or filter_value is None:
                raise errors.IncorrectRequestError()
            sessions = Session.query.filter_by(problem_id=problem_id)
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            sessions = sessions.join(User)
            if len(filter_value) >= 3 and filter_value[0:2] == '.g':
                sessions = sessions.filter(
                    User.university_group.ilike('{}%'.format(filter_value[2:]))
                )
            else:
                sessions = sessions.filter(
                    (User.last_name + ' ' + User.first_name + ' ' + User.middle_name).ilike('{}%'.format(filter_value))
                )
            session_count = sessions.count()
            sessions = sessions.order_by(Session.unchecked_attempt_count.desc(), Session.id.asc())
            response_data_array = []
            for session in sessions:
                response_data_array.append(
                    {
                        'sessionID': session.id,
                        'studentFullName': session.student.full_name(),
                        'studentGroup': session.student.university_group,
                        'studentAvatarPath': session.student.avatar_url,
                        'unverifiedAttemptCount': session.unchecked_attempt_count,
                        'sessionHasNewCommentariesForTeacher': False
                    }
                )
            return {
                       'message': 'success',
                       'sessionInfo': response_data_array,
                       'sessionCount': session_count
                   }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()


class AdminGetSession(Resource):
    method_decorators = {
        'get': [session_token_check],
        'post': [session_token_check]
    }

    def get(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            request_args = request.args
            session_id = request_args.get('sessionID')
            if session_id is None:
                raise errors.IncorrectRequestError()
            session = Session.query.filter_by(id=session_id).first()
            if session is None:
                raise errors.SessionNotFoundError()
            attempts = []
            for attempt in session.attempts:
                attempts.append({
                    'studentAttempt': attempt.student_attempt.for_transmitting(),
                    'attemptHasNewCommentary': False,
                    'teacherFeedbackStatus': attempt.teacher_feedback.status.title if attempt.teacher_feedback is not None else '',
                })
            return {
                       'message': 'success',
                       'attempts': attempts
                   }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def post(*args, **kwargs):
        try:
            data = request.get_json()
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            attempt_id = data.get('attemptID')
            if attempt_id is None:
                raise errors.IncorrectRequestError()
            attempt = Attempt.query.filter_by(id=attempt_id).first()
            if attempt is None:
                raise errors.AttemptNotFoundError()
            response = {
                'teacherFeedback': attempt.teacher_feedback.for_transmitting(
                    True) if attempt.teacher_feedback is not None else None,
                'commentaries': []
            }
            for commentary in attempt.commentaries:
                response['commentaries'].append(commentary.for_transmitting())
            response[
                'teacherFeedbackStatus'] = attempt.teacher_feedback.status.title if attempt.teacher_feedback is not None else ''
            db.session.commit()
            return {
                       'message': 'success',
                       'attempt': response
                   }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class AdminGetProblemInformation(Resource):
    method_decorators = {
        'get': [session_token_check]
    }

    def get(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            problem_id = kwargs.get('problem_id')
            if problem_id is None:
                raise errors.IncorrectRequestError()
            problem = Problem.query.filter_by(id=problem_id).first()
            if problem is None:
                raise errors.ProblemNotFoundError()
            data = {
                'problemRejectionReason': problem.rejection_reason if problem.problem_status.title == 'Отклонена' else '',
                'authorFullName': problem.author.full_name(),
                'authorID': problem.author.id,
                'authorGroup': problem.author.university_group,
                'authorAvatarPath': problem.author.avatar_url,
                'authorCommentary': problem.author_commentary,
                'problemID': problem.id,
                'problemTitle': problem.title,
                'problemStatus': problem.problem_status.title,
                'problemDiscipline': problem.discipline,
                'problemComplexity': problem.problem_complexity.title if problem.problem_complexity is not None else '',
                'problemStartLine': date_to_str(problem.start_date_of_making_decision),
                'problemDeadline': date_to_str(problem.end_date_of_making_decision),
                'problemPath': problem.problem_file_URL
            }
            return {
                'message': 'success',
                'data': data
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

def admin_commentary_deleting(commentary_id):
    commentary = Commentary.query.filter_by(id=commentary_id).first()
    if commentary is None:
        raise errors.CommentaryNotFoundError()
    author = commentary.author
    if commentary.attempt.session.student_id == author.id:
        down_student(author, False)
    else:
        down_teacher(commentary.author, False)
    db.session.delete(commentary)
    return []

def admin_teacher_feedback_deleting(attempt_id):
    attempt = Attempt.query.filter_by(id=attempt_id).first()
    if attempt is None:
        raise errors.AttemptNotFoundError()
    if attempt.teacher_feedback is None:
        raise errors.IncorrectRequestError()
    file_path = attempt.teacher_feedback.file_url
    down_teacher(attempt.session.problem.author, False)
    if attempt.student_attempt.status.title == 'Попытка проверена учителем':
        new_status = StudentAttemptStatus.query.filter_by(title='Попытка проверяется учителем').first()
        attempt.student_attempt.status = new_status
    db.session.delete(attempt.teacher_feedback)
    return [file_path]

def admin_student_attempt_deleting(attempt_id):
    attempt = Attempt.query.filter_by(id=attempt_id).first()
    if attempt is None:
        raise errors.AttemptNotFoundError()
    file_for_deleting = []
    if attempt.teacher_feedback is not None:
        file_for_deleting.append(attempt.teacher_feedback.file_url)
    file_for_deleting.append(attempt.student_attempt.file_url)
    for image in attempt.student_attempt.images:
        file_for_deleting.append(image.path)
    if len(attempt.session.attempts) == 1:
        db.session.delete(attempt.session)
    db.session.delete(attempt)
    down_student(attempt.session.student, False)
    return file_for_deleting

def admin_problem_deleting(problem_id):
    problem = Problem.query.filter_by(id=problem_id).first()
    if problem is None:
        raise errors.ProblemNotFoundError()
    files_for_deleting = []
    for session in problem.sessions:
        for attempt in session.attempts:
            files_for_deleting.append('../' + attempt.student_attempt.file_url)
            for image in attempt.student_attempt.images:
                db.session.delete(image)
                files_for_deleting.append('../' + image.path)
            if attempt.teacher_feedback is not None:
                files_for_deleting.append('../' + attempt.teacher_feedback.file_url)
        db.session.delete(session)
    files_for_deleting.append('../' + problem.problem_file_URL)
    db.session.delete(problem)
    down_teacher(problem.author, False)
    return files_for_deleting

DELETE_METHOD = {
    'commentary': admin_commentary_deleting,
    'student attempt': admin_student_attempt_deleting,
    'teacher feedback': admin_teacher_feedback_deleting,
    'problem': admin_problem_deleting
}

class AdminTargetDeleting(Resource):
    method_decorators = {
        'put': [csrf_token_check]
    }

    def put(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            data = args[len(args) - 1]
            target_id = data.get('targetID')
            target_mode = data.get('targetMode')
            if target_mode is None or target_id is None or target_mode not in DELETE_METHOD:
                raise errors.IncorrectRequestError()
            files_for_deleting = DELETE_METHOD[target_mode](target_id)
            db.session.commit()
            for file in files_for_deleting:
                os.remove('../' + file)
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            traceback.print_exc()
            raise errors.DatabaseError()


class AdminInformation(Resource):
    method_decorators = {
        'get': [session_token_check],
        'post': [csrf_token_check]
    }

    def get(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            data = request.args
            label = data.get('label')
            if label is None:
                raise errors.IncorrectRequestError()
            if label == 'adminHelp' and not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            information = Information.query.filter_by(label=label).first()
            if information is None:
                raise errors.InformationNotFound()
            return {
                'message': 'success',
                'information': information.text
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            label = data.get('label')
            new_text = data.get('text')
            if label is None or new_text is None:
                raise errors.IncorrectRequestError()
            information = Information.query.filter_by(label=label).first()
            if information is None:
                raise errors.InformationNotFound()
            information.text = new_text
            db.session.commit()
            return {
                'message': 'success'
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()


class ProblemDisciplineAPI(Resource):
    method_decorators = {
        'get': [session_token_check],
        'post': [csrf_token_check],
        'put': [csrf_token_check]
    }

    def get(*args, **kwargs):
        try:
            user = args[len(args) - 1]
            if not role_check(user, 'Учитель'):
                raise errors.PermissionDeniedError()
            problem_disciplines = ProblemDiscipline.query.all()
            response = []
            for problem_discipline in problem_disciplines:
                response.append(problem_discipline.for_transmitting())
            return {
                'message': 'success',
                'data':response
            }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def post(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            label = data.get('label')
            if label is None:
                raise errors.IncorrectRequestError()
            new_discipline = ProblemDiscipline(label)
            db.session.add(new_discipline)
            db.session.flush()
            new_discipline_id = new_discipline.id
            db.session.commit()
            return {
                'message': 'success',
                'id': new_discipline_id
            }, 201
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()

    def put(*args, **kwargs):
        try:
            user = args[len(args) - 2]
            data = args[len(args) - 1]
            if not role_check(user, 'Администратор', 'Помощник администратора'):
                raise errors.PermissionDeniedError()
            task_discipline_id = data.get('id')
            if task_discipline_id is None:
                raise errors.IncorrectRequestError()
            target_discipline = ProblemDiscipline.query.filter_by(id=task_discipline_id).first()
            if target_discipline is None:
                raise errors.ProblemDisciplineNotFound()
            db.session.delete(target_discipline)
            db.session.commit()
            return {
                       'message': 'success',
                   }, 200
        except exc.SQLAlchemyError:
            raise errors.DatabaseError()




api.add_resource(AdminGetAllProblemsByTeacher, '/api/admin/get-problems/<string:user_id>')
api.add_resource(AdminGetAllSessionsByStudent, '/api/admin/get-sessions/<string:user_id>')
api.add_resource(AdminGetSessionsByProblem, '/api/admin/get-sessions-by-problem/<string:problem_id>')
api.add_resource(AdminGetProblemInformation, '/api/admin/get-problem-information/<string:problem_id>')
api.add_resource(AdminGetSession, '/api/admin/get-session')
api.add_resource(AdminGetProblem, '/api/admin/problems')
api.add_resource(AdminGetUser, '/api/admin/users')
api.add_resource(AdminChangeRole, '/api/admin/change-role')
api.add_resource(AdminStatistic, '/api/admin/get-statistic')
api.add_resource(AdminTargetDeleting, '/api/admin/delete-target')
api.add_resource(AdminInformation, '/api/admin/information')
api.add_resource(ProblemDisciplineAPI, '/api/admin/problem-discipline')


api.add_resource(AsTeacherGetProblemAPI, '/api/teacher/problems')
api.add_resource(AsStudentGetProblemsAPI, '/api/student/problems')
api.add_resource(HideStatusAPI, '/api/hide-status')
api.add_resource(Logout, '/api/logout')
api.add_resource(AttemptCheckAPI, '/api/check-attempt/<string:attempt_id>')
api.add_resource(CommentaryAPI, '/api/commentary-editing')
api.add_resource(AttemptEditingAPI, '/api/attempt-editing')
api.add_resource(GetAttemptAPI, '/api/get-attempt')
api.add_resource(ProblemEditingAPI, '/api/problem-editing')
api.add_resource(AddProblemAPI, '/api/add-problem')
api.add_resource(GeneralProblemAPI, '/api/problem/<string:problem_id>')
api.add_resource(ProblemAdmittingAPI, '/api/admitting-problem/<string:problem_id>')
api.add_resource(SessionAPI, '/api/session-for-problem/<string:problem_id>')
api.add_resource(PasswordChanger, '/api/change-password')
api.add_resource(RecallPassword, '/api/recall-password')
api.add_resource(Registration, '/api/registration')
api.add_resource(Login, '/api/login')
api.add_resource(RoleCheck, '/api/role-check')
api.add_resource(ActivatingCodeCheck, '/api/account-activation')
api.add_resource(RestoreUserData, '/api/restore-data')
api.add_resource(AuthenticationCheck, '/api/authentication-check')

if __name__ == '__main__':
    app.run()

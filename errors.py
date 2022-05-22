from werkzeug.exceptions import HTTPException
import constants

errorsDict = {
    'IncorrectEmailAddressError': {
        'message': "incorrect email",
        'status': 400
    },
    'UserAlreadyExistsError': {
        'message': 'user already exists',
        'status': 400
    },
    'DatabaseError': {
        'message': 'database error',
        'status': 500
    },
    'InternalServerError': {
        'message': 'internal error',
        'status': 500
    },
    'SMTPError': {
        'message': 'SMTP error',
        'status': 500
    },
    'IncorrectLoginError': {
        'message': 'wrong login',
        'status': 403
    },
    'IncorrectPasswordError': {
        'message': 'wrong password',
        'status': 403
    },
    'ARTimeIntervalError': {
        'message': 'time interval has not passed',
        'status': 403,
        'intervalLength': constants.CONST_ACTIVATING_CODE_REQUEST_INTERVAL
    },
    'ACTimeIntervalError': {
        'message': 'time interval has not passed',
        'status': 403,
        'intervalLength': constants.CONST_ACTIVATING_CODE_CHECK_INTERVAL
    },
    'PRTimeIntervalError': {
        'message': 'time interval has not passed',
        'status': 403,
        'intervalLength': constants.CONST_NEW_PASSWORD_CODE_REQUEST_INTERVAL
    },
    'PCTimeIntervalError': {
        'message': 'time interval has not passed',
        'status': 403,
        'intervalLength': constants.CONST_NEW_PASSWORD_CODE_CHECK_INTERVAL
    },
    'CodeExpiredError': {
        'message': 'code expired',
        'status': 403
    },
    'AccountNotFoundError': {
        'message': 'account not found',
        'status': 404
    },
    'WrongCodeError': {
        'message': 'wrong code',
        'status': 403
    },
    'AuthenticationError': {
        'message': 'need authentication',
        'status': 401
    },
    'TexConversionError': {
        'message': 'tex conversion failed',
        'status': 400
    },
    'NotTeacherError': {
        'message': 'user is not a teacher',
        'status': 403
    },
    'ProblemDeletedError': {
        'message': 'problem deleted',
        'status': 404
    },
    'IncorrectRequestError': {
        'message': 'incorrect request',
        'status': 422
    },
    'NotAuthorError': {
        'message': 'not author',
        'status': 403
    },
    'ProblemNotFoundError': {
        'message': 'problem not found',
        'status': 404
    },
    'NotAdminError': {
        'message': 'not admin',
        'status': 403
    },
    'ProblemAlreadyAdmittedError': {
        'message': 'problem already admitted',
        'status': 400
    },
    'AttemptAlreadyCheckedError': {
        'message': 'attempt already checked',
        'status': 400
    },
    'ProblemIsAdmittingError': {
        'message': 'problem is admitting',
        'status': 403
    },
    'SessionNotFoundError': {
        'message': 'session not found',
        'status': 404
    },
    'AttemptNotFoundError': {
        'message': 'attempt not found',
        'status': 404
    },
    'PermissionDeniedError': {
        'message': 'permission denied',
        'status': 403
    },
    'CommentaryNotFoundError': {
        'message': 'commentary not found',
        'status': 404
    },
    'PDFFromPNGError': {
        'message': 'pdf creating failed',
        'status': 500
    },
    'UserNotFound': {
        'message': 'user not found',
        'status': 404
    },
    'UserAlreadyAdmin': {
        'message': 'user already admin',
        'status': 400
    },
    'SessionStatusNotFound': {
        'message': 'session status not found',
        'status': 404
    },
    'ProblemIsAdmittingNow': {
        'message': 'problem is admitting now',
        'status': 403
    },
    'InformationNotFound': {
        'message': 'information not found',
        'status': 404
    },
    'AttemptCanNotBeAdded': {
        'message': 'attempt can not be added',
        'status': 403
    },
    'UserAlreadyActivated': {
        'message': 'user already activated',
        'status': 400
    },
    'ProblemDisciplineNotFound': {
        'message': 'discipline not found',
        'status': 404
    }
}


class ProblemDisciplineNotFound(HTTPException):
    pass


class UserAlreadyActivated(HTTPException):
    pass


class AttemptCanNotBeAdded(HTTPException):
    pass


class InformationNotFound(HTTPException):
    pass


class ProblemIsAdmittingNow(HTTPException):
    pass


class SessionStatusNotFound(HTTPException):
    pass


class UserAlreadyAdmin(HTTPException):
    pass


class UserNotFound(HTTPException):
    pass


class PDFFromPNGError(HTTPException):
    pass


class AttemptAlreadyCheckedError(HTTPException):
    pass


class CommentaryNotFoundError(HTTPException):
    pass


class PermissionDeniedError(HTTPException):
    pass


class AttemptNotFoundError(HTTPException):
    pass


class SessionNotFoundError(HTTPException):
    pass


class ProblemIsAdmittingError(HTTPException):
    pass


class ProblemAlreadyAdmittedError(HTTPException):
    pass


class NotAdminError(HTTPException):
    pass


class ProblemNotFoundError(HTTPException):
    pass


class NotAuthorError(HTTPException):
    pass


class IncorrectRequestError(HTTPException):
    pass


class ProblemDeletedError(HTTPException):
    pass


class NotTeacherError(HTTPException):
    pass


class AuthenticationError(HTTPException):
    pass


class TexConversionError(HTTPException):
    pass


class WrongCodeError(HTTPException):
    pass


class AccountNotFoundError(HTTPException):
    pass


class CodeExpiredError(HTTPException):
    pass


class IncorrectEmailAddressError(HTTPException):
    pass


class UserAlreadyExistsError(HTTPException):
    pass


class DatabaseError(HTTPException):
    pass


class InternalServerError(HTTPException):
    pass


class SMTPError(HTTPException):
    pass


class IncorrectLoginError(HTTPException):
    pass


class IncorrectPasswordError(HTTPException):
    pass


class ARTimeIntervalError(HTTPException):
    pass


class ACTimeIntervalError(HTTPException):
    pass


class PRTimeIntervalError(HTTPException):
    pass


class PCTimeIntervalError(HTTPException):
    pass

from app import Role, ProblemStatus, ProblemComplexity, SessionStatus, SolutionDegree, StudentAttemptStatus, TeacherFeedbackStatus, db
import constants


def init_select_role(needed_role_titles, class_name):
    roles_in_db = class_name.query.all()
    for role_title in needed_role_titles:
        flag = False
        for role_in_db in roles_in_db:
            if role_title == role_in_db.title:
                flag = True
                break
        if not flag:
            db.session.add(class_name(role_title))
    db.session.commit()


init_select_role(constants.CONST_ROLE_TITLES, Role)
init_select_role(constants.CONST_STATUS_TITLES, ProblemStatus)
init_select_role(constants.CONST_COMPLEXITY_TITLES, ProblemComplexity)
init_select_role(constants.CONST_SESSION_STATUS_TITLES, SessionStatus)
init_select_role(constants.CONST_SOLUTION_DEGREES, SolutionDegree)
init_select_role(constants.CONST_TEACHER_FEEDBACK_STATUS, TeacherFeedbackStatus)
init_select_role(constants.CONST_STUDENT_ATTEMPT_STATUS, StudentAttemptStatus)

# CONST_SERVER_URL = 'http://78.81.147.165'
CONST_SERVER_URL = 'http://192.168.100.6'
CONST_PROBLEM_ID_LENGTH = 20
CONST_ACTIVATING_CODE_LENGTH = 10
CONST_NEW_PASSWORD_CODE_LENGTH = 10
CONST_CSRF_TOKEN_LENGTH = 40  # in symbols
CONST_SESSION_TOKEN_LENGTH = 32  # in bytes
# IN SECONDS
CONST_ACTIVATING_CODE_REQUEST_INTERVAL = 60 * 5
CONST_ACTIVATING_CODE_CHECK_INTERVAL = 60 * 1
CONST_ACTIVATING_CODE_TTL = 60 * 60
CONST_NEW_PASSWORD_CODE_REQUEST_INTERVAL = 60 * 5
CONST_NEW_PASSWORD_CODE_CHECK_INTERVAL = 60 * 1
CONST_NEW_PASSWORD_CODE_TTL = 60 * 60
CONST_SESSION_TOKEN_TTL = 60 * 60 * 24
CONST_PROBLEM_ADMITTING_ATTEMPT_INTERVAL = 60 * 10
CONST_TEX_MIME_TYPE = ['application/x-latex',
                       'application/x-tex',
                       'text/x-latex',
                       'text/x-tex'
                       ]
CONST_STATUS_TITLES = ['Проверяется', 'Принята', 'Отклонена', 'Скрыта', 'Заблокирована']
CONST_ROLE_TITLES = ['Ученик', 'Учитель', 'Администратор', 'Помощник администратора']
CONST_COMPLEXITY_TITLES = ['Простая', 'Средняя', 'Сложная']
CONST_SESSION_STATUS_TITLES = ['Открыта', 'Заблокирована']
CONST_STUDENT_ATTEMPT_STATUS = ['Попытка не просмотрена учителем', 'Попытка проверяется учителем', 'Попытка проверена учителем']
CONST_TEACHER_FEEDBACK_STATUS = ['Отзыв просмотрен учеником', 'Отзыв не просмотрен учеником', 'Черновик отзыва']
CONST_SOLUTION_DEGREES = ['Пока не решена', 'Есть идея', 'Почти решена', 'Полностью решена', '']

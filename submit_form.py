#!/usr/bin/env python3

import cgi
import http.cookies
import re
import pymysql
from datetime import datetime, timedelta
import os
import secrets
import hashlib
import html

def create_connection():
    try:
        return pymysql.connect(
            host='158.160.182.8',
            user='u68593',
            password='9258357',
            database='web_db',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print(f"Ошибка подключения к базе данных: {html.escape(str(e))}")
        return None

def validate_form(data):
    errors = {}
    patterns = {
        'last_name': r'^[А-Яа-яЁё]+$',
        'first_name': r'^[А-Яа-яЁё]+$',
        'patronymic': r'^[А-Яа-яЁё]*$',
        'phone': r'^\+?\d{10,15}$',
        'email': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
        'birthdate': r'^\d{4}-\d{2}-\d{2}$',
        'bio': r'^.{10,}$'
    }
    messages = {
        'last_name': "Фамилия должна содержать только буквы кириллицы.",
        'first_name': "Имя должно содержать только буквы кириллицы.",
        'patronymic': "Отчество должно содержать только буквы кириллицы (если указано).",
        'phone': "Телефон должен быть длиной от 10 до 15 цифр и может начинаться с '+'",
        'email': "Некорректный email. Пример: example@domain.com",
        'birthdate': "Дата рождения должна быть в формате YYYY-MM-DD.",
        'bio': "Биография должна содержать не менее 10 символов."
    }

    for field, pattern in patterns.items():
        if field in data and not re.match(pattern, data[field]):
            errors[field] = messages[field]

    if 'gender' not in data or data['gender'] not in ['male', 'female']:
        errors['gender'] = "Выберите пол."

    if 'languages' not in data or not data['languages']:
        errors['languages'] = "Выберите хотя бы один язык программирования."

    if 'contract' not in data or not data['contract']:
        errors['contract'] = "Необходимо подтвердить ознакомление с контрактом."

    return errors

def generate_html_form(data, errors, is_logged_in=False, credentials=None):
    # Escape all user-provided data before output
    escaped_data = {k: html.escape(v) if isinstance(v, str) else v for k, v in data.items()}
    
    login_section = ""
    if not is_logged_in:
        login_section = """
        <div class="login-section">
            <h2>Вход</h2>
            <form action="submit_form.py" method="POST">
                <input type="hidden" name="action" value="login">
                <label for="username">Логин:</label>
                <input type="text" id="username" name="username" required>
                
                <label for="password">Пароль:</label>
                <input type="password" id="password" name="password" required>
                
                <button type="submit">Войти</button>
            </form>
        </div>
        """
    
    credentials_section = ""
    if credentials:
        credentials_section = f"""
        <div class="credentials">
            <h3>Ваши учетные данные (сохраните их):</h3>
            <p><strong>Логин:</strong> {html.escape(credentials['username'])}</p>
            <p><strong>Пароль:</strong> {html.escape(credentials['password'])}</p>
        </div>
        """
    
    logout_button = ""
    if is_logged_in:
        logout_button = """
        <form action="submit_form.py" method="POST">
            <input type="hidden" name="action" value="logout">
            <button type="submit" class="logout-button">Выйти</button>
        </form>
        """

    html_template = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Форма</title>
        <link rel="stylesheet" href="styles.css">
    </head>
    <body>
        {login_section}
        {credentials_section}
        {logout_button}
        
        <form action="submit_form.py" method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            
            <label for="last_name">Фамилия:</label>
            <input type="text" id="last_name" name="last_name" maxlength="50" required
                   value="{last_name}" class="{last_name_error_class}">
            <span class="error-message">{last_name_error}</span><br>

            <!-- Rest of the form fields with escaped values -->
            <!-- ... -->
        </form>
    </body>
    </html>
    """
    
    # Generate CSRF token
    csrf_token = secrets.token_hex(32)
    
    context = {
        'login_section': login_section,
        'credentials_section': credentials_section,
        'logout_button': logout_button,
        'csrf_token': csrf_token,
        'last_name': escaped_data.get('last_name', ''),
        'first_name': escaped_data.get('first_name', ''),
        'patronymic': escaped_data.get('patronymic', ''),
        'phone': escaped_data.get('phone', ''),
        'email': escaped_data.get('email', ''),
        'birthdate': escaped_data.get('birthdate', ''),
        'male_checked': 'checked' if escaped_data.get('gender') == 'male' else '',
        'female_checked': 'checked' if escaped_data.get('gender') == 'female' else '',
        'pascal_selected': 'selected' if 'Pascal' in escaped_data.get('languages', []) else '',
        'c_selected': 'selected' if 'C' in escaped_data.get('languages', []) else '',
        'cpp_selected': 'selected' if 'C++' in escaped_data.get('languages', []) else '',
        'javascript_selected': 'selected' if 'JavaScript' in escaped_data.get('languages', []) else '',
        'php_selected': 'selected' if 'PHP' in escaped_data.get('languages', []) else '',
        'python_selected': 'selected' if 'Python' in escaped_data.get('languages', []) else '',
        'java_selected': 'selected' if 'Java' in escaped_data.get('languages', []) else '',
        'haskel_selected': 'selected' if 'Haskel' in escaped_data.get('languages', []) else '',
        'clojure_selected': 'selected' if 'Clojure' in escaped_data.get('languages', []) else '',
        'prolog_selected': 'selected' if 'Prolog' in escaped_data.get('languages', []) else '',
        'scala_selected': 'selected' if 'Scala' in escaped_data.get('languages', []) else '',
        'go_selected': 'selected' if 'Go' in escaped_data.get('languages', []) else '',
        'bio': escaped_data.get('bio', ''),
        'contract_checked': 'checked' if escaped_data.get('contract') else '',
        'last_name_error': html.escape(errors.get('last_name', '')),
        'first_name_error': html.escape(errors.get('first_name', '')),
        'patronymic_error': html.escape(errors.get('patronymic', '')),
        'phone_error': html.escape(errors.get('phone', '')),
        'email_error': html.escape(errors.get('email', '')),
        'birthdate_error': html.escape(errors.get('birthdate', '')),
        'gender_error': html.escape(errors.get('gender', '')),
        'languages_error': html.escape(errors.get('languages', '')),
        'bio_error': html.escape(errors.get('bio', '')),
        'contract_error': html.escape(errors.get('contract', '')),
        'last_name_error_class': 'error' if 'last_name' in errors else '',
        'first_name_error_class': 'error' if 'first_name' in errors else '',
        'patronymic_error_class': 'error' if 'patronymic' in errors else '',
        'phone_error_class': 'error' if 'phone' in errors else '',
        'email_error_class': 'error' if 'email' in errors else '',
        'birthdate_error_class': 'error' if 'birthdate' in errors else '',
        'bio_error_class': 'error' if 'bio' in errors else ''
    }

    return html_template.format(**context)

def generate_credentials():
    username = secrets.token_hex(8)
    password = secrets.token_hex(8)
    return {'username': username, 'password': password}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def insert_user_data(connection, data, credentials=None):
    cursor = connection.cursor()
    try:
        if credentials:
            # Use parameterized queries to prevent SQL injection
            cursor.execute("""
                UPDATE applications 
                SET last_name=%s, first_name=%s, patronymic=%s, phone=%s, email=%s, 
                    birthdate=%s, gender=%s, bio=%s, contract=%s
                WHERE username=%s
            """, (
                data['last_name'], data['first_name'], data['patronymic'],
                data['phone'], data['email'], data['birthdate'],
                data['gender'], data['bio'], data['contract'],
                credentials['username']
            ))
            
            cursor.execute("SELECT id FROM applications WHERE username=%s", (credentials['username'],))
            result = cursor.fetchone()
            application_id = result['id'] if result else None
        else:
            credentials = generate_credentials()
            hashed_password = hash_password(credentials['password'])
            
            cursor.execute("""
                INSERT INTO applications 
                (last_name, first_name, patronymic, phone, email, birthdate, 
                 gender, bio, contract, username, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data['last_name'], data['first_name'], data['patronymic'],
                data['phone'], data['email'], data['birthdate'],
                data['gender'], data['bio'], data['contract'],
                credentials['username'], hashed_password
            ))
            
            application_id = cursor.lastrowid

        if not application_id:
            raise Exception("Не удалось получить ID заявки")

        cursor.execute("DELETE FROM application_languages WHERE application_id=%s", (application_id,))

        language_ids = {
            'Pascal': 1, 'C': 2, 'C++': 3, 'JavaScript': 4, 'PHP': 5,
            'Python': 6, 'Java': 7, 'Haskel': 8, 'Clojure': 9,
            'Prolog': 10, 'Scala': 11, 'Go': 12
        }

        for language in data['languages']:
            language_id = language_ids.get(language)
            if language_id:
                cursor.execute("""
                    INSERT INTO application_languages (application_id, language_id)
                    VALUES (%s, %s)
                """, (application_id, language_id))
        
        connection.commit()
        return credentials
        
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print(f"<h1>Ошибка базы данных: {html.escape(str(e))}</h1>")
        connection.rollback()
        return None
    except Exception as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print(f"<h1>Ошибка: {html.escape(str(e))}</h1>")
        connection.rollback()
        return None
    finally:
        cursor.close()

def verify_user(connection, username, password):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT id, password_hash FROM applications WHERE username=%s
        """, (username,))
        result = cursor.fetchone()
        if result:
            hashed_password = hash_password(password)
            if result['password_hash'] == hashed_password:
                return True
        return False
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print(f"Ошибка при вставке данных: {html.escape(str(e))}")
        return None
    finally:
        cursor.close()

def get_user_data(connection, username):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT a.*, GROUP_CONCAT(pl.name) as languages
            FROM applications a
            LEFT JOIN application_languages al ON a.id = al.application_id
            LEFT JOIN programming_languages pl ON al.language_id = pl.id
            WHERE a.username=%s
            GROUP BY a.id
        """, (username,))
        result = cursor.fetchone()
        
        if not result:
            return None
            
        data = {
            'last_name': result['last_name'],
            'first_name': result['first_name'],
            'patronymic': result['patronymic'],
            'phone': result['phone'],
            'email': result['email'],
            'birthdate': result['birthdate'],
            'gender': result['gender'],
            'languages': result['languages'].split(',') if result['languages'] else [],
            'bio': result['bio'],
            'contract': result['contract']
        }
        
        return data
    except pymysql.Error as e:
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print(f"Ошибка при вставке данных: {html.escape(str(e))}")
        return None
    finally:
        cursor.close()

if __name__ == "__main__":
    cookie = http.cookies.SimpleCookie()
    cookie.load(os.environ.get('HTTP_COOKIE', ''))
    
    form = cgi.FieldStorage()
    request_method = os.environ.get('REQUEST_METHOD', '')
    
    action = form.getvalue('action')
    
    if action == 'login' and request_method == 'POST':
        username = form.getvalue('username', '').strip()
        password = form.getvalue('password', '').strip()
        
        connection = create_connection()
        if connection:
            if verify_user(connection, username, password):
                session_id = secrets.token_hex(16)
                cookie['session_id'] = session_id
                cookie['session_id']['path'] = '/'
                cookie['session_id']['expires'] = (datetime.now() + timedelta(days=1)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                cookie['session_id']['httponly'] = True
                cookie['session_id']['samesite'] = 'Strict'
                
                cursor = connection.cursor()
                try:
                    cursor.execute("""
                        INSERT INTO sessions (session_id, username, expires_at)
                        VALUES (%s, %s, %s)
                    """, (
                        session_id,
                        username,
                        datetime.now() + timedelta(days=1)
                    ))
                    connection.commit()
                finally:
                    cursor.close()
                
                print("Content-Type: text/html; charset=utf-8")
                print("Status: 303 See Other")
                print("Location: submit_form.py")
                print(cookie.output())
                print("\n")
                connection.close()
                exit()
            connection.close()
        
        print("Content-Type: text/html; charset=utf-8")
        print("\n")
        print("<h1>Неверный логин или пароль</h1>")
        exit()
    
    elif action == 'logout' and request_method == 'POST':
        session_id = cookie.get('session_id')
        if session_id:
            connection = create_connection()
            if connection:
                cursor = connection.cursor()
                try:
                    cursor.execute("""
                        DELETE FROM sessions WHERE session_id=%s
                    """, (session_id.value,))
                    connection.commit()
                finally:
                    cursor.close()
                connection.close()
            
            cookie['session_id'] = ''
            cookie['session_id']['path'] = '/'
            cookie['session_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        
        print("Content-Type: text/html; charset=utf-8")
        print("Status: 303 See Other")
        print("Location: submit_form.py")
        print(cookie.output())
        print("\n")
        exit()
    
    is_logged_in = False
    username = None
    session_id = cookie.get('session_id')
    
    if session_id:
        connection = create_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("""
                    SELECT username FROM sessions 
                    WHERE session_id=%s AND expires_at > NOW()
                """, (session_id.value,))
                result = cursor.fetchone()
                if result:
                    is_logged_in = True
                    username = result['username']
            finally:
                cursor.close()
            connection.close()
    
    data = {
        'last_name': form.getvalue('last_name', '').strip(),
        'first_name': form.getvalue('first_name', '').strip(),
        'patronymic': form.getvalue('patronymic', '').strip(),
        'phone': form.getvalue('phone', '').strip(),
        'email': form.getvalue('email', '').strip(),
        'birthdate': form.getvalue('birthdate', '').strip(),
        'gender': form.getvalue('gender', '').strip(),
        'languages': form.getlist('languages[]'),
        'bio': form.getvalue('bio', '').strip(),
        'contract': 'contract' in form 
    }

    if is_logged_in and not any(data.values()):
        connection = create_connection()
        if connection:
            user_data = get_user_data(connection, username)
            if user_data:
                data.update(user_data)
            connection.close()
    
    elif not any(data.values()):
        for field in data.keys():
            if field in cookie:
                data[field] = cookie[field].value

    if request_method == 'POST' and not action:
        # Verify CSRF token
        if not is_logged_in or (is_logged_in and form.getvalue('csrf_token') == cookie.get('csrf_token').value):
            errors = validate_form(data)

            if errors:
                for field, message in errors.items():
                    cookie[field + '_error'] = message
                    cookie[field + '_error']['path'] = '/'
                    cookie[field + '_error']['expires'] = 0

                print("Content-Type: text/html; charset=utf-8")
                print(cookie.output())
                print("\n")
                print(generate_html_form(data, errors, is_logged_in))
            else:
                for field in data.keys():
                    if f'{field}_error' in cookie:
                        del cookie[f'{field}_error']

                for field, value in data.items():
                    cookie[field] = value
                    cookie[field]['path'] = '/'
                    cookie[field]['expires'] = (datetime.now() + timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')

                connection = create_connection()
                if connection:
                    if is_logged_in:
                        credentials = insert_user_data(connection, data, {'username': username})
                        success_message = "<h1>Данные успешно обновлены</h1>"
                    else:
                        credentials = insert_user_data(connection, data)
                        if credentials:
                            success_message = f"""
                            <h1>Данные успешно сохранены</h1>
                            <div class="credentials">
                                <h3>Ваши учетные данные (сохраните их):</h3>
                                <p><strong>Логин:</strong> {html.escape(credentials['username'])}</p>
                                <p><strong>Пароль:</strong> {html.escape(credentials['password'])}</p>
                            </div>
                            """
                        else:
                            success_message = "<h1>Ошибка при сохранении данных</h1>"
                    connection.close()
                else:
                    success_message = "<h1>Ошибка подключения к базе данных</h1>"

                print("Content-Type: text/html; charset=utf-8")
                print(cookie.output())
                print("\n")
                print(success_message)
        else:
            print("Content-Type: text/html; charset=utf-8")
            print("\n")
            print("<h1>Ошибка CSRF токена</h1>")
    else:
        credentials = None
        if 'show_credentials' in cookie and cookie['show_credentials'].value == 'true':
            credentials = {
                'username': cookie['username'].value,
                'password': cookie['password'].value
            }
            cookie['show_credentials'] = ''
            cookie['show_credentials']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        
        # Generate and set CSRF token for logged-in users
        if is_logged_in:
            csrf_token = secrets.token_hex(32)
            cookie['csrf_token'] = csrf_token
            cookie['csrf_token']['path'] = '/'
            cookie['csrf_token']['httponly'] = True
            cookie['csrf_token']['samesite'] = 'Strict'
        
        print("Content-Type: text/html; charset=utf-8")
        print(cookie.output())
        print("\n")
        print(generate_html_form(data, {}, is_logged_in, credentials))

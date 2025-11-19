from flask import Flask, render_template, request, jsonify, redirect, Response
import threading
from server import server_class
import os

app = Flask(__name__)

server=server_class(test_mode=True)

@app.route('/')
def index():
    return render_template("index.html", title="Главная", content="Добро пожаловать в панель управления!")

inner_menu_status = [
        {"name": "Общий статус", "url": "/status"},
        {"name": "Логи", "url": "/status/logs"},
        {"name": "Конечные точки", "url": "/status/endpoints"}
    ]
@app.route('/status')
def status():
    return render_template("status.html", title="Статус", active='status', inner_menu=inner_menu_status, content="Сервис работает корректно.")


CHUNK_SIZE=250
LINES_TO_LOAD=500
@app.route('/status/logs')
def status_logs():
    total_lines = 0
    try:
        file_handler=server.slogger.handlers[0]
        LOG_FILE=file_handler.baseFilename
    except Exception as E:
        server.slogger.error(f'ERR retrieving log filename {E}. Using default server.log')
        LOG_FILE='server.log'
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            total_lines = sum(1 for _ in f)
    else:
        total_lines=0
        
    start_line = max(total_lines - LINES_TO_LOAD, 0)
    available_lines = total_lines - start_line



    return render_template(
        "status/logs.html",
        title="Логи системы",
        inner_menu=inner_menu_status,
        total_lines=available_lines,
        chunk_size=CHUNK_SIZE
    )

@app.route('/status/logs/data')
def get_logs_chunk():
    chunk = int(request.args.get("chunk", 0))
    lines = []

    try:
        file_handler=server.slogger.handlers[0]
        LOG_FILE=file_handler.baseFilename
    except Exception as E:
        server.slogger.error(f'ERR retrieving log filename {E}. Using default server.log')
        LOG_FILE='server.log'

    if not os.path.exists(LOG_FILE):
        return jsonify({"lines": []})

    # Считаем общее количество строк
    with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        all_lines = f.readlines()

    # Берём только последние LINES_TO_LOAD строк
    recent_lines = all_lines[-LINES_TO_LOAD:] if len(all_lines) > LINES_TO_LOAD else all_lines

    # Определяем диапазон строк для отображения
    start = chunk * CHUNK_SIZE
    end = start + CHUNK_SIZE
    lines = recent_lines[start:end]

    return jsonify({"lines": [line.strip() for line in lines]})

@app.route('/status/endpoints')
def endpoints():
    table_headers,table_data=server.get_status('clients')
    return render_template("status/endpoints.html", title="Конечные точки", active='endpoints', inner_menu=inner_menu_status, table_headers=table_headers,
        table_data=table_data)

inner_menu_users = [
        {"name": "Обзор", "url": "/users"},
        {"name": "Создать пользователя", "url": "/users/create"},
        {"name": "Удалить пользователя", "url": "/users/remove"}
    ]
@app.route('/users')
def users():
    #данные в таблицу запрашивает js
    return render_template("users.html", title="Пользователи", active='Обзор', inner_menu=inner_menu_users)

@app.route("/users_refresh", methods=["POST"])
def users_refresh():
    server.pull_users()
    return redirect("/users")

@app.route('/users/get')
def get_users_filtered():
    filter = str(request.args.get("filter", ''))
    headers,lines=server.get_status('users', filter)
    table=[]
    table.append(headers)
    for row in lines:
        table.append(row)
    return jsonify(table)

@app.route('/users/create')
def users_create():
    _, clients=server.get_status('clients_for_exec')
    labels, values=[], []
    for i in range(len(clients)):
        temp=f'{clients[i][0]} {clients[i][2]}'
        labels.append(temp)
        values.append(clients[i][1])
    check_boxes=zip(values, labels)
    return render_template("/users/create.html", title="Создать пользователя", active='Создать пользователя', inner_menu=inner_menu_users, options_data=check_boxes)

@app.route('/users/create/submit', methods=["POST"])
def users_create_submit():
    username=request.form.get('username')
    password=request.form.get('pass1')
    hosts=request.form.getlist('options')
    try:
        server.create_user_task(username, password, hosts)
    except Exception as E:
        return Response("Ошибка при создании пользователя: {E}", mimetype="text/plain")
    return redirect('/tasks')

inner_menu_tasks = [
        {"name": "Обзор", "url": "/tasks"},
        {"name": "Создать задание", "url": "/tasks/create"}
    ]
@app.route('/tasks')
def tasks():
    table_headers, table_data=server.get_status('tasks')
    return render_template("tasks.html", title="Задания", active='Обзор', inner_menu=inner_menu_tasks, table_headers=table_headers,
    table_data=table_data)

@app.route("/task/<task_id>")
def task_info(task_id:str):
    table_headers, table_data=server.get_status('task', task_id)
    return render_template("tasks/task.html", title="Задание", active='', inner_menu=inner_menu_tasks, table_headers=table_headers,
    table_data=table_data)

@app.route('/tasks/create')
def tasks_create():
    _, clients=server.get_status('clients_for_exec')
    labels, values=[], [],
    for i in range(len(clients)):
        temp=f'{clients[i][0]} {clients[i][2]}'
        labels.append(temp)
        values.append(clients[i][1])
    check_boxes=zip(values, labels)
    return render_template("tasks/create.html", title="Новое задание", active='Создать задание', inner_menu=inner_menu_tasks, options_data=check_boxes)

@app.route("/tasks/create/submit", methods=["POST"])
def tasks_create_submin():
    text_value = request.form.get("textInput")           # Получаем текстовое поле
    selected_options = request.form.getlist("options")   # Получаем список выбранных чекбоксов
    for clients_str in selected_options:
        server.add_command(bytes.fromhex(clients_str), 'exec', text_value.encode())
        pass
    return redirect('/tasks')

@app.route('/settings')
def settings():
    return render_template("settings.html", title="Настройки", content="Здесь будут настройки системы.")

class web():
    def __init__(self, host:str, port:int):
        self.host=host
        self.port=port
        server_thread = threading.Thread(target=self.run_server, daemon=True)
        server_thread.start()

    def run_server(self):
        app.run(host=self.host, port=self.port, debug=False, use_reloader=False)

def run_thread():
    app.run(host="0.0.0.0", port=51234)

if __name__ == "__main__":
    server_thread = threading.Thread(target=run_thread, daemon=True)
    server_thread.start()
    server.create_client(filename='./clients/testing_client2.json')
    server.listen_for_connections()
from flask import Flask, render_template, request, jsonify, redirect, Response, send_file
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
    arg=str(request.args.get("arg", ''))
    if arg=='delete':
        filter = str(request.args.get("filter", ''))
        users=server.USERS.read_all(filter)
        table=[]
        for usr in users:
            row=[]
            row.append(usr[0].hex())
            row.append(usr[1])
            row.append(server.clients.dict[usr[0]]['alias'])
            row.append('' if usr[3]==0 else 'NO LOGIN')
            table.append(row)
        return jsonify(table)
    else:
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

@app.route('/users/remove')
def users_remove():


    return render_template("/users/remove.html", title="Удалить пользователя", active='Удалить пользователя', inner_menu=inner_menu_users)

@app.route('/users/remove/submit', methods=["POST"])
def users_remove_submit():
    options=request.form.getlist('options')
    try:
        result, s_res=server.remove_user_task(options)
    except Exception as E:
        server.slogger.error(f"Ошибка при удалении пользователя: {E}")
        return Response(f"Ошибка при удалении пользователя: {E}", mimetype="text/plain")
    if not result:
        return Response(f"Ошибки при удалении некоторых пользователей: {s_res}", mimetype="text/plain")
    return redirect('/tasks')

@app.route('/users/create/submit', methods=["POST"])
def users_create_submit():
    username=request.form.get('username')
    password=request.form.get('pass1')
    hosts=request.form.getlist('options')
    try:
        result, s_res=server.create_user_task(username, password, hosts)
    except Exception as E:
        server.slogger.error(f"Ошибка при создании пользователя: {E}")
        return Response(f"Ошибка при создании пользователя: {E}", mimetype="text/plain")
    if not result:
        return Response(f"Ошибки при создании некоторых пользователей: {s_res}", mimetype="text/plain")
    return redirect('/tasks')

inner_menu_tasks = [
        {"name": "Обзор", "url": "/tasks"},
        {"name": "Создать задание", "url": "/tasks/create"}
    ]
@app.route('/tasks')
def tasks():
    table_headers, table_data=server.get_status('tasks')
    return render_template("tasks.html", title="Задания", active='Обзор', 
    inner_menu=inner_menu_tasks, table_headers=table_headers,
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


inner_menu_settings = [
        {"name": "Основные настройки", "url": "/settings"},
        {"name": "Добавить АРМ", "url": "/create_client"},
        {"name": "Удалить АРМ", "url": "/remove_client"},
    ]

@app.route('/settings',  methods=["GET", "POST"])
def settings():
    tpm_support=server.conf.check_tpm()
    if tpm_support:
        TPMactive=server.conf.tpm_active
    try:
        vals={
            'controlserverip':server.conf.settings['SERVER_IP'],
            'controlserverpub':server.conf.settings['s_pub_ip'],
            'controlserverport':server.conf.settings['SERVER_PORT'],
            'webserverip':server.conf.settings['SERVER_WEB_IP'],
            'webserverport':server.conf.settings['SERVER_WEB_PORT'],
        }
    except Exception as E:
        vals={
            'controlserverip':f'ERR {E}',
            'controlserverpub':'',
            'controlserverport':'',
            'webserverip':'',
            'webserverport':'',
        }
    if request.method=="GET":
        return render_template("settings.html", title="Управление",
                            vals=vals,
                            inner_menu=inner_menu_settings,
                            active='Основные настройки',
                            TPM=tpm_support)
    else:
        server.conf.settings['SERVER_IP']=request.form.get('controlserverip')
        server.conf.settings['s_pub_ip']=request.form.get('controlserverpub')
        server.conf.settings['SERVER_PORT']=request.form.get('controlserverport')
        server.conf.settings['SERVER_WEB_IP']=request.form.get('webserverip')
        server.conf.settings['SERVER_WEB_PORT']=request.form.get('webserverport')
        server.conf.save()

        try:
            vals={
                'controlserverip':server.conf.settings['SERVER_IP'],
                'controlserverpub':server.conf.settings['s_pub_ip'],
                'controlserverport':server.conf.settings['SERVER_PORT'],
                'webserverip':server.conf.settings['SERVER_WEB_IP'],
                'webserverport':server.conf.settings['SERVER_WEB_PORT'],
            }
        except Exception as E:
            vals={
                'controlserverip':f'ERR {E}',
                'controlserverpub':'',
                'controlserverport':'',
                'webserverip':'',
                'webserverport':'',
            }
        result=f'Settings updated. Now you need to restart server'

        return render_template("settings.html", title="Управление",
                            vals=vals,
                            inner_menu=inner_menu_settings,
                            active='Основные настройки', result=result,
                            TPM=tpm_support)
    
@app.route('/create_client', methods=["GET", "POST"])
def arm_add():
    if request.method == 'POST':
        alias=request.form.get('arm-name')
        cfg=server.create_client(alias)
        config_b64=cfg.export_b64()
        final_str=f'client --live-conf {config_b64}'
        return render_template("settings/add.html", title="Добавить АРМ",
                            result=final_str,
                            inner_menu=inner_menu_settings,
                            active='Добавить АРМ')
    else:
        return render_template("settings/add.html", title="Добавить АРМ",
                    inner_menu=inner_menu_settings,
                    active='Добавить АРМ')

@app.route('/remove_client', methods=["GET", "POST"])
def arm_remove():
    if request.method == 'POST':
        hosts=request.form.getlist('options')
        final_str=''
        for host in hosts:
            try:
                server.remove_client(host)
            except Exception as E:
                final_str+=f'{E}\n'
        _, clients=server.get_status('clients_for_exec')
        labels, values=[], [],
        for i in range(len(clients)):
            temp=f'{clients[i][0]} {clients[i][2]}'
            labels.append(temp)
            values.append(clients[i][1])
        check_boxes=zip(values, labels)
        return render_template("settings/remove.html", title="Удалить АРМ",
                            result=final_str,
                            inner_menu=inner_menu_settings,
                            active='Удалить АРМ',
                            options_data=check_boxes)
    else:
        _, clients=server.get_status('clients_for_exec')
        labels, values=[], [],
        for i in range(len(clients)):
            temp=f'{clients[i][0]} {clients[i][2]}'
            labels.append(temp)
            values.append(clients[i][1])
        check_boxes=zip(values, labels)
        return render_template("settings/remove.html", title="Удалить АРМ",
                    inner_menu=inner_menu_settings,
                    active='Удалить АРМ',
                    options_data=check_boxes)


@app.route('/download_client')
def dowload_client():
    return send_file('./dist/client.exe')
class web():
    def __init__(self, host:str, port:int):
        self.host=host
        self.port=port
        server_thread = threading.Thread(target=self.run_server, daemon=True)
        server_thread.start()

    def run_server(self):
        app.run(host=self.host, port=self.port, debug=False, use_reloader=False)

def run_thread():
    app.run(host=server.conf.settings['SERVER_WEB_IP'], port=server.conf.settings['SERVER_WEB_PORT'])

if __name__ == "__main__":
    server_thread = threading.Thread(target=run_thread, daemon=True)
    server_thread.start()
    #server.create_client(filename='./clients/testing_client2.json')
    server.listen_for_connections()
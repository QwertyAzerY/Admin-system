import logging
import logging.handlers
import sys
import io

stream = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Настройка логгера
""" logging.basicConfig(
    level=logging.INFO,  # Устанавливаем уровень логирования (DEBUG/INFO/WARNING/ERROR)
    format='%(asctime)s - %(levelname)s - %(message)s',  # Формат логов
    handlers=[
        logging.FileHandler("app.log", mode='a'),  # Лог файл
        logging.StreamHandler(stream),  # Вывод логов на консоль
        logging.handlers.RotatingFileHandler("app.log", maxBytes=1024*1024*5)
    ]
) """

# Создаем логгер, который можно импортировать
slogger = logging.getLogger("server")
slogger.setLevel(logging.INFO)

s_handler=logging.FileHandler("server.log", mode="a", encoding="utf-8")
s_formatter=logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
s_handler.setFormatter(s_formatter)
slogger.addHandler(s_handler)
slogger.addHandler(logging.StreamHandler(stream))
slogger.addHandler(logging.handlers.RotatingFileHandler("server.log", maxBytes=1024*1024*5))

clogger = logging.getLogger("client")
clogger.setLevel(logging.INFO)

c_handler=logging.FileHandler("client.log", mode="a", encoding="utf-8")
c_formatter=logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
c_handler.setFormatter(c_formatter)
clogger.addHandler(c_handler)
clogger.addHandler(logging.StreamHandler(stream))
clogger.addHandler(logging.handlers.RotatingFileHandler("client.log", maxBytes=1024*1024*5))
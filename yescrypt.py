import sys
import getpass
import shutil
import subprocess

def use_crypt_module(password: str) -> str:
    try:
        import crypt
    except Exception:
        raise RuntimeError("Модуль crypt недоступен в этой среде Python.")

    # Проверяем, есть ли константа METHOD_YESCRYPT (современные установки)
    method_yescrypt = getattr(crypt, "METHOD_YESCRYPT", None)

    if method_yescrypt is not None:
        # безопасно используем crypt.mksalt с системным методом yescrypt
        salt = crypt.mksalt(method_yescrypt)
        return crypt.crypt(password, salt)

    # Если константа не доступна, попробуем спросить crypt.methods()
    try:
        methods = getattr(crypt, "methods", None)
        if methods:
            for m in crypt.methods():
                # иногда методы() возвращает строковые id, а crypt.mksalt принимает константу;
                # если в методах есть 'yescrypt' — попробуем crypt.mksalt('yescrypt') (rare)
                if isinstance(m, str) and "yescrypt" in m.lower():
                    try:
                        salt = crypt.mksalt(m)
                        return crypt.crypt(password, salt)
                    except Exception:
                        pass
    except Exception:
        pass

    raise RuntimeError("Модуль crypt присутствует, но не поддерживает yescrypt на этой системе.")

def use_shadowhash_cli(password: str) -> str:
    """
    fallback: если установлена утилита shadowhash (pip install shadowhash),
    она по умолчанию генерирует yescrypt-строку совместимую с /etc/shadow.
    """
    exe = shutil.which("shadowhash")
    if not exe:
        raise RuntimeError("Утилита 'shadowhash' не найдена в PATH.")
    # shadowhash принимает пароль в argv (внимание: видно в ps); можно передать через stdin
    p = subprocess.run([exe], input=(password + "\n").encode(), capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"shadowhash вернула ошибку: {p.stderr.decode().strip()}")
    return p.stdout.decode().strip()

def main():
    try:
        pw = getpass.getpass("Password: ")
    except (KeyboardInterrupt, EOFError):
        print("\nОтменено.", file=sys.stderr)
        sys.exit(1)

    # сначала пытаемся через crypt (лучше всего — даёт 100% совместимость)
    try:
        out = use_crypt_module(pw)
        print(out)
        return
    except Exception as e:
        # не фатальная ошибка — покажем fallback-предложение
        sys.stderr.write("crypt module fallback: " + str(e) + "\n")

    # fallback: попробуем вызвать shadowhash CLI (pip install shadowhash)
    try:
        out = use_shadowhash_cli(pw)
        print(out)
        return
    except Exception as e:
        sys.stderr.write("shadowhash fallback: " + str(e) + "\n")

    # если ничего не удалось — подсказка пользователю
    sys.stderr.write(
        "\nНе удалось сгенерировать yescrypt-хеш автоматически.\n\n"
        "Рекомендации:\n"
        "  1) На Linux лучше всего использовать системный модуль crypt (он обёртка над crypt(3)/libxcrypt).\n"
        "     Убедитесь, что вы запускаете Python, который поставляется с вашей системой (не чистый Win/PyEnv),\n"
        "     или установите пакет-переносимую реализацию crypt: `pip install crypt-r`.\n\n"
        "  2) Установите утилиту shadowhash и используйте её (она по умолчанию генерирует yescrypt):\n"
        "       pip install shadowhash\n"
        "     после этого повторно запустите этот скрипт — он попробует вызвать локальную утилиту.\n\n"
        "  3) Если вам нужна чисто-Python реализация yescrypt: посмотрите 'pyescrypt' (pip install pyescrypt),\n"
        "     но учтите — формат `/etc/shadow` требует точного кодирования опций и соль/хэш в том формате,\n"
        "     который формирует libxcrypt; удобнее оставить эту задачу системной библиотеке.\n"
    )
    sys.exit(2)

if __name__ == "__main__":
    main()
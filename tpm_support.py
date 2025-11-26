class my_tpm():

    def __init__(self, nv_path="/nv/Owner/system_key"):
        from tpm2_pytss import FAPI
        self.fapi = FAPI()
        self.NV_PATH=nv_path

        # Инициализация FAPI (если не делали)
        self.fapi.provision()

    def save(self, data):
        # Если NV уже существует — удалить
        try:
            self.fapi.delete(self.NV_PATH)
        except Exception:
            pass

        # Создать NV область
        self.fapi.create_nv(
            path=self.NV_PATH,
            size=len(data),
            type_="noDa",      # тип NV
            policy_path=None,
            auth_value=""
        )

        # Запись
        self.fapi.nv_write(
            path=self.NV_PATH,
            data=data
        )
        return True
    
    def read(self):
        # Чтение
        read = self.fapi.nv_read(self.NV_PATH)
        print("Прочитано из TPM:", read)
        return read




# if __name__ == "__main__":
#     tpm=my_tpm()
#     tpm.save(bytes(i for i in range(256)))
#     tpm.read()
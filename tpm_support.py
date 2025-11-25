from tpm2_pytss import *
from tpm2_pytss.binding import *

# Ваши данные (массив байтов)
data_to_store = b"\x01\x02\x03\x04\x05TEST_SECRET"

# Контекст TPM
esys = ESAPI()

# Создаём первичный ключ (primary key) в иерархии Owner
primary_template = TPM2B_PUBLIC(
    publicArea=TPMT_PUBLIC(
        type=TPM2_ALG_RSA,
        nameAlg=TPM2_ALG_SHA256,
        objectAttributes=(
            TPMA_OBJECT_RESTRICTED
            | TPMA_OBJECT_DECRYPT
            | TPMA_OBJECT_FIXEDTPM
            | TPMA_OBJECT_FIXEDPARENT
            | TPMA_OBJECT_SENSITIVEDATAORIGIN
            | TPMA_OBJECT_USERWITHAUTH
        ),
        parameters=TPMU_PUBLIC_PARMS(
            rsaDetail=TPMS_RSA_PARMS(
                symmetric=TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG_AES, keyBits=TPMU_SYM_KEY_BITS(sym=128), mode=TPMU_SYM_MODE(sym=TPM2_ALG_CFB)),
                scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG_NULL),
                keyBits=2048,
                exponent=0,
            )
        ),
        unique=TPMU_PUBLIC_ID(rsa=TPM2B_PUBLIC_KEY_RSA()),
    )
)

primary_handle, _, _, _, _ = esys.CreatePrimary(
    ESYS_TR_RH_OWNER,
    ESYS_TR_PASSWORD,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    TPM2B_SENSITIVE_CREATE(),
    primary_template,
    None,
    None,
)

# Создаём sealed-объект (запечатываем байты)
in_sensitive = TPM2B_SENSITIVE_CREATE(
    sensitive=TPMS_SENSITIVE_CREATE(
        userAuth=b"",
        data=data_to_store
    )
)

seal_template = TPM2B_PUBLIC(
    publicArea=TPMT_PUBLIC(
        type=TPM2_ALG_KEYEDHASH,
        nameAlg=TPM2_ALG_SHA256,
        objectAttributes=(
            TPMA_OBJECT_FIXEDTPM
            | TPMA_OBJECT_FIXEDPARENT
            | TPMA_OBJECT_SENSITIVEDATAORIGIN
            | TPMA_OBJECT_USERWITHAUTH
        ),
        parameters=TPMU_PUBLIC_PARMS(
            keyedHashDetail=TPMS_KEYEDHASH_PARMS(
                scheme=TPMT_KEYEDHASH_SCHEME(scheme=TPM2_ALG_NULL)
            )
        ),
        unique=TPMU_PUBLIC_ID(keyedHash=TPM2B_DIGEST()),
    )
)

private, public, _, _ = esys.Create(
    primary_handle,
    ESYS_TR_PASSWORD,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    in_sensitive,
    seal_template,
    None,
    None,
)

# Сохраняем ключ и данные на диск
with open("sealed_private.bin", "wb") as f:
    f.write(bytes(private))

with open("sealed_public.bin", "wb") as f:
    f.write(bytes(public))

print("Данные успешно запечатаны и сохранены в sealed_private.bin / sealed_public.bin")
from __future__ import annotations

from shared.keys import KeyMaterial, serialize_key_material


def main() -> None:
    auth_key, enc_key = serialize_key_material(KeyMaterial.generate())
    print('SCK_CSD_MODE = "embedded"')
    print(f'SCK_AUTH_KEY = "{auth_key}"')
    print(f'SCK_ENC_KEY = "{enc_key}"')


if __name__ == "__main__":
    main()

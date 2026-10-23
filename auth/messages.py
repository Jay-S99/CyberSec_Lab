from localization import translate as translate_ui


def translate(code, language=None, **params):
    selected = language if language is not None else None
    key = f"messages.{code}"
    translated = translate_ui(key, language=selected, **params)
    if translated == key:
        return translate_ui(
            "messages.invalid_request",
            language=selected,
        )
    return translated

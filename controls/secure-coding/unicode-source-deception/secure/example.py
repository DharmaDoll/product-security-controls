"""Unicode text is allowed as data while identifiers remain reviewable."""

message = "日本語の文字列はデータとして許可されます"
review_count = len(message)


def display_message(value: str) -> str:
    return f"message={value}"


print(display_message(message), review_count)

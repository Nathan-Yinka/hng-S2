def standard_response(status: str, message: str, data: dict = None):
    response = {
        "status": status,
        "message": message,
    }
    if data is not None:
        response["data"] = data
    return response


def format_validation_errors(errors):
    formatted_errors = []
    for field, messages in errors.items():
        for message in messages:
            formatted_errors.append({
                "field": field,
                "message": message
            })
    return formatted_errors
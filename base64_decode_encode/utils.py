from flask import jsonify, request


def get_response(response, status):
    return jsonify({"response": response}), status


def get_data():
    if request.is_json:
        data = request.get_json().get("data")
    else:
        data = request.form.get("data")

    return data


def require_data(f):
    def wrapper(*args, **kwargs):
        data = get_data()
        if not data:
            return get_response('Error: "data" is required', 400)

        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__  # Preserve function name
    return wrapper

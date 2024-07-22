from django.contrib.auth import get_backends

def get_user_backend(user):
    for backend in get_backends():
        if backend.get_user(user.pk):
            return f"{backend.__module__}.{backend.__class__.__name__}"
    return None

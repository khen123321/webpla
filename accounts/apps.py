from django.apps import AppConfig

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'  # replace with your actual app name if it's different

    def ready(self):
        import accounts.models  # this line ensures the signals in models.py get loaded
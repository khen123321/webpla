from django.contrib import admin
from .models import OTP, Profile

admin.site.register(OTP)
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'signup_source', 'points', 'profile_image_preview')
    list_filter = ('signup_source',)
    readonly_fields = ('signup_source',)

    def profile_image_preview(self, obj):
        if obj.profile_pic:
            return f'<img src="{obj.profile_pic.url}" style="height: 50px; border-radius: 5px;" />'
        return "No Image"
    profile_image_preview.allow_tags = True
    profile_image_preview.short_description = 'Profile Picture'

# Don't customize User admin - let the signal handle Profile creation automatically
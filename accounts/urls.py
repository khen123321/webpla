from django.urls import path
from . import views
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from .views import ForgotPasswordView, ResetPasswordView
from .views import SendOTPView, VerifyOTPView, ResetPasswordView


@csrf_exempt
@require_http_methods(["GET"])
def get_csrf_token(request):
    return JsonResponse({'csrfToken': request.META.get('CSRF_COOKIE', '')})

urlpatterns = [
    # Web views
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('rewards/', views.rewards_view, name='rewards'),
    path('claim-requests/', views.claim_requests_view, name='claim_requests'),
    path('approve-claim/<int:claim_id>/', views.approve_claim_request, name='approve_claim'),
    path('reject-claim/<int:claim_id>/', views.reject_claim_request, name='reject_claim'),
    path('profile/', views.profile_view, name='profile'),
    path('users/', views.users_view, name='users'),
    path('users/suggest/', views.user_suggestions, name='user_suggestions'),
    path('forgot/', views.forgot_password_view, name='forgot_password'),
    path('send-otp/', views.send_otp, name='send_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),

    # API endpoints
    path('api/csrf-token/', get_csrf_token, name='get_csrf_token'),
    path('api/signup/', csrf_exempt(views.api_signup), name='api_signup'),
    path('api/login/', csrf_exempt(views.api_login), name='api_login'),
    path('api/get-points/', csrf_exempt(views.api_get_user_points), name='api_get_user_points'),
    path('api/rewards/', csrf_exempt(views.api_get_rewards), name='api_get_rewards'),
    path('api/claim-reward/', csrf_exempt(views.api_claim_reward), name='api_claim_reward'),
    path('api/claim-history/', csrf_exempt(views.api_get_claim_history), name='api_get_claim_history'),
    path('api/upload-profile-pic/', csrf_exempt(views.upload_profile_pic), name='upload_profile_pic'),
    path('api/scan-qr/', csrf_exempt(views.scan_qr_code), name='scan_qr_code'),  # Remove the 'e'
    path('api/receive-count/', csrf_exempt(views.api_receive_count), name='api_receive_count'),
    path("api/update-bottle/", csrf_exempt(views.update_bottle_count), name="update_bottle_count"),
    path('api/get-redemption-details/', views.api_get_redemption_details, name='api_get_redemption_details'),
    path('signup/', views.signup, name='signup'),
    path('api/login/', csrf_exempt(views.login_user), name='api_login_user'),

    


    



    
    # New endpoints for profile editing
    path('api/update-profile/', csrf_exempt(views.api_update_profile), name='api_update_profile'),
    path('api/change-password/', csrf_exempt(views.api_change_password), name='api_change_password'),
    path('api/get-profile/', csrf_exempt(views.api_get_profile), name='api_get_profile'),
]
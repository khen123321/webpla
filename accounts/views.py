# views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate
from django.contrib.auth import logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from .models import Profile
from .models import Reward
from .models import ClaimRequest
from .forms import RewardForm 
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.core.files.base import ContentFile
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import base64
import re
import json
from django.db import models
from django.utils.timezone import now
from datetime import timedelta
from datetime import datetime 
from django.core.mail import send_mail
from django.conf import settings
from .serializers import RewardSerializer  # Make sure this import is at the top
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import Reward
from .serializers import RewardSerializer
from django.db.models import Q
from django.contrib.auth import authenticate, login
from django.middleware.csrf import get_token
from django.db.models.functions import TruncMonth
from django.db.models import Count
from django.template.defaulttags import register
from rest_framework.views import APIView
from rest_framework import status
from .utils import generate_and_send_otp
from .models import EmailOTP
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
import random
from .models import OTP
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ObjectDoesNotExist
from .models import PasswordResetOTP
from rest_framework import generics
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .serializers import SendOTPSerializer, VerifyOTPSerializer, ResetPasswordSerializer
from .models import PasswordResetOTP
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from .serializers import ForgotPasswordOTPSerializer, VerifyForgotPasswordOTPSerializer


OTP_STORE = {}

User = get_user_model()


# 1️⃣ Send OTP for Forgot Password
@api_view(['POST'])
@permission_classes([AllowAny])
def send_forgot_password_otp(request):
    serializer = ForgotPasswordOTPSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'success': False, 'message': 'User not found'}, status=404)

        # Generate OTP
        code = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(minutes=10)

        # Save OTP
        PasswordResetOTP.objects.create(user=user, otp=code)

        # Send email
        send_mail(
        'Your OTP Code',
         f'Your OTP is {code}. It expires in 10 minutes.',
         settings.EMAIL_HOST_USER,
         [email],
        fail_silently=False
        )

        return Response({'success': True, 'message': 'OTP sent to your email'}, status=200)
    return Response(serializer.errors, status=400)


# 2️⃣ Reset Password (Fixed Logic)
@csrf_exempt
def reset_password(request):
    if request.method != "POST":
        return JsonResponse({"message": "Invalid request method"}, status=400)

    try:
        data = json.loads(request.body)
        email = data.get('email')
        otp = data.get('otp')
        new_password = data.get('new_password')

        if not all([email, otp, new_password]):
            return JsonResponse({"message": "All fields are required"}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({"message": "User not found"}, status=404)

        otp_obj = PasswordResetOTP.objects.filter(user=user, otp=otp).first()
        if not otp_obj or otp_obj.is_expired():
         return Response({"otp": ["Invalid OTP"]}, status=400)

# reset password
        user.set_password(new_password)
        user.save()
        otp_obj.delete()

    

        return JsonResponse({"message": "Password reset successful"}, status=200)

    except Exception as e:
        return JsonResponse({"message": str(e)}, status=400)


# 3️⃣ Forgot Password View (Alternative APIView)
class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "No account associated with this email"}, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP
        otp_code = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(minutes=10)
        PasswordResetOTP.objects.create(user=user, otp=otp_code)

        send_mail(
            'Password Reset OTP',
            f'Your password reset OTP is {otp_code}. It expires in 10 minutes.',
            'noreply@yourapp.com',
            [email],
        )

        return Response({"message": "OTP sent successfully"}, status=status.HTTP_200_OK)


# 4️⃣ Serializer for Reset Password
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8, write_only=True)

    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User does not exist"})

        otp_obj = PasswordResetOTP.objects.filter(user=user, otp=data['otp']).last()
        if not otp_obj:
            raise serializers.ValidationError({"otp": "Invalid OTP"})
        if otp_obj.is_expired():
            raise serializers.ValidationError({"otp": "OTP expired"})

        data['user'] = user
        data['otp_obj'] = otp_obj
        return data

    def save(self):
        user = self.validated_data['user']
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        self.validated_data['otp_obj'].delete()
        return user


# 5️⃣ Send OTP View (Generic)

@method_decorator(csrf_exempt, name='dispatch')
class SendOTPView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required"}, status=400)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        # Generate OTP
        otp_code = PasswordResetOTP.generate_otp()
        try:
            otp_obj = PasswordResetOTP.objects.create(user=user, otp=otp_code)
        except Exception as e:
            print(f"❌ Error sending OTP: {e}")
            return Response({"error": str(e)}, status=500)
        
        print(f"📨 OTP for {email}: {otp_code}")
        return Response({"message": f"OTP sent to {email}", "otp": otp_code}, status=200)

# 6️⃣ Verify OTP View
@method_decorator(csrf_exempt, name='dispatch')
class VerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        otp_obj = PasswordResetOTP.objects.filter(user=user, otp=otp).first()
        if not otp_obj or otp_obj.is_expired():
            return Response({"otp": ["Invalid OTP"]}, status=400)

        # ✅ Do NOT delete OTP here
        return Response({"success": True, "message": "OTP verified successfully"}, status=200)


# 7️⃣ Reset Password View (Final API)
@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")

        if not email or not otp or not new_password:
            return Response({"error": "Missing fields"}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        otp_obj = PasswordResetOTP.objects.filter(user=user, otp=otp).first()
        if not otp_obj or otp_obj.is_expired():
            return Response({"otp": ["Invalid OTP"]}, status=400)

        # ✅ Reset password
        user.set_password(new_password)
        user.save()

        # ✅ Delete OTP after success
        otp_obj.delete()

        return Response({"message": "Password reset successful"}, status=200)

def signup(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            # For now, just confirm the data came through
            print("📨 Signup data received:", data)

            # Simulate a created user response (so your React app doesn't break)
            user_data = {
                "id": 1,
                "username": data.get("username"),
                "email": data.get("email"),
                "first_name": data.get("first_name"),
                "last_name": data.get("last_name"),
                "address": data.get("address"),
                "phone_number": data.get("phone_number"),
                "birth_date": data.get("birth_date"),
                "profile_pic": None,
            }

            return JsonResponse({"message": "Signup successful", "user": user_data}, status=201)

        except Exception as e:
            print("❌ Signup error:", str(e))
            return JsonResponse({"error": "Invalid request"}, status=400)

    return JsonResponse({"error": "Invalid method"}, status=405)


@register.filter
def multiply(value, arg):
    return value * arg


@api_view(['GET'])
def get_csrf_token(request):
    return Response({'csrfToken': get_token(request)})


@login_required
def user_suggestions(request):
    query = request.GET.get('q', '').strip().lower()
    results = []

    if query and len(query) >= 2:
        # ✅ Only search mobile app users
        users = User.objects.filter(
            Q(username__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query),
            profile__signup_source='mobile'  # Only mobile users
        ).exclude(id=request.user.id)[:10]

        for user in users:
            display_name = []
            if user.first_name or user.last_name:
                display_name.append(f"{user.first_name} {user.last_name}".strip())
            display_name.append(f"@{user.username}")

            display_str = " - ".join(filter(None, [
                " ".join(display_name),
                user.email
            ]))
            results.append(display_str)

    return JsonResponse({'results': results})

@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return JsonResponse({'message': 'Username and password required'}, status=400)

            # Try Django authenticate first
            user = authenticate(username=username, password=password)

            if user is None:
                # If that fails, manually check (in case password wasn’t hashed)
                try:
                    user_obj = User.objects.get(username=username)
                    if check_password(password, user_obj.password) or user_obj.password == password:
                        user = user_obj
                except User.DoesNotExist:
                    user = None

            if user is not None:
                user_data = {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                }
                return JsonResponse({'message': 'Login successful', 'user': user_data}, status=200)
            else:
                return JsonResponse({'message': 'Invalid credentials'}, status=401)

        except Exception as e:
            return JsonResponse({'message': f'Error: {str(e)}'}, status=500)

    return JsonResponse({'message': 'Invalid request method'}, status=405)

@csrf_exempt
@require_http_methods(["POST"])
def api_get_user_points(request):
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        
        # Get the user
        user = User.objects.get(id=user_id)
        
        # Ensure profile exists
        try:
            profile = user.profile
        except ObjectDoesNotExist:
            profile = Profile.objects.create(user=user)
        
        points = profile.points
        
        return JsonResponse({'success': True, 'points': points})
    
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=404)
    
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)
    
@csrf_exempt
@require_http_methods(["POST"])
def api_change_password(request):
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        user = User.objects.get(id=user_id)
        
        if not user.check_password(current_password):
            return JsonResponse({'success': False, 'message': 'Current password is incorrect'}, status=400)
        
        user.set_password(new_password)
        user.save()
        
        return JsonResponse({'success': True, 'message': 'Password updated successfully'})
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_claim_reward(request):
    try:
        data = json.loads(request.body)
        reward_id = data.get('reward_id')
        user_id = data.get('user_id')

        reward = Reward.objects.get(id=reward_id)
        user = User.objects.get(id=user_id)
        profile = Profile.objects.get(user_id=user_id)

        if profile.points < reward.cost:
            return JsonResponse({'success': False, 'message': 'Not enough points'}, status=400)

        if reward.remaining_quantity() <= 0:
            return JsonResponse({'success': False, 'message': 'Reward out of stock'}, status=400)

        # Check if user already has a pending request for this reward
        existing_request = ClaimRequest.objects.filter(
            user=user, 
            reward=reward, 
            status='pending'
        ).first()
        
        if existing_request:
            return JsonResponse({'success': False, 'message': 'You already have a pending request for this reward'}, status=400)

        # Create a pending claim request
        claim_request = ClaimRequest.objects.create(
            user=user,
            reward=reward,
            status='pending'
        )

        return JsonResponse({
            'success': True, 
            'message': 'Claim request submitted successfully. Please wait for admin approval.',
            'claim_id': claim_request.id,
            'unique_id': claim_request.unique_id  # Add this line
        })
    except Reward.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Reward not found'}, status=404)
    except Profile.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Profile not found'}, status=404)
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)

@api_view(['GET'])
def api_get_rewards(request):
    rewards = Reward.objects.all()
    serializer = RewardSerializer(rewards, many=True, context={'request': request})
    return Response(serializer.data)


@csrf_exempt
@require_http_methods(["POST"])
def api_get_profile(request):
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        
        if not user_id:
            return JsonResponse({'success': False, 'message': 'User ID is required'}, status=400)
        
        user = User.objects.get(id=user_id)
        profile, created = Profile.objects.get_or_create(user=user)
        
        if created:
            # ✅ Set as mobile user if created via API
            profile.signup_source = 'mobile'
            profile.save()
        
        # Ensure signup_source is set for existing profiles from mobile
        if not profile.signup_source:
            profile.signup_source = 'mobile'
            profile.save()
            
        response_data = {
            'success': True,
            'profile': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'address': profile.address,
                'phone_number': profile.phone_number,
                'birth_date': profile.birth_date.isoformat() if profile.birth_date else None,
                'profile_pic': request.build_absolute_uri(profile.profile_pic.url) if profile.profile_pic else None,
                'points': profile.points,
                'signup_source': profile.signup_source  # Include in response
            }
        }
        
        return JsonResponse(response_data)
    
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)
    

@login_required
def rewards_view(request):
    if request.method == 'POST':
        # Handle delete first
        if 'delete_id' in request.POST:
            delete_id = request.POST.get('delete_id')
            if delete_id:
                reward = get_object_or_404(Reward, id=delete_id)
                reward.delete()
                messages.success(request, 'Reward deleted successfully.')
                return redirect('rewards')
        
        # Handle add/edit reward
        edit_id = request.POST.get('edit_id')
        name = request.POST.get('name')
        available = request.POST.get('available') == 'True'
        cost = int(request.POST.get('cost', 0))
        total_quantity = int(request.POST.get('total_quantity', 0))
        reset_claimed = request.POST.get('reset_claimed') == 'on'
        
        if edit_id:
            # Editing existing reward
            reward = get_object_or_404(Reward, id=edit_id)
            reward.name = name
            reward.available = available
            
            # Handle points and quantity based on availability
            if available:
                reward.cost = cost
                reward.total_quantity = total_quantity
                
                # Check if quantity changed and reset claimed count if requested
                if reset_claimed or int(total_quantity) != reward.total_quantity:
                    reward.claimed_count = 0
            else:
                # If not available, set to 0
                reward.cost = 0
                reward.total_quantity = 0
                reward.claimed_count = 0
                
        else:
            # Creating new reward
            if available:
                reward = Reward(
                    name=name,
                    available=available,
                    cost=cost,
                    total_quantity=total_quantity,
                    claimed_count=0
                )
            else:
                reward = Reward(
                    name=name,
                    available=available,
                    cost=0,
                    total_quantity=0,
                    claimed_count=0
                )
        
        # Handle image upload
        if 'image' in request.FILES:
            reward.image = request.FILES['image']
        
        reward.save()
        messages.success(request, f'Reward {"updated" if edit_id else "created"} successfully.')
        return redirect('rewards')

    rewards = Reward.objects.all()
    return render(request, 'accounts/rewards.html', {'rewards': rewards})

@login_required
def claim_requests_view(request):
    """View for admin to manage claim requests"""
    pending_requests = ClaimRequest.objects.filter(status='pending').order_by('-requested_at')
    processed_requests = ClaimRequest.objects.filter(status__in=['approved', 'rejected']).order_by('-processed_at')[:20]  # Last 20 processed
    
    context = {
        'pending_requests': pending_requests,
        'processed_requests': processed_requests,
    }
    return render(request, 'accounts/claim_requests.html', context)


@login_required 
def approve_claim_request(request, claim_id):
    """Approve a claim request and deduct points"""
    if request.method == 'POST':
        try:
            claim_request = get_object_or_404(ClaimRequest, id=claim_id, status='pending')
            
            # Get the claim by date from the form
            claim_by_date_str = request.POST.get('claim_by_date')
            if claim_by_date_str:
                from datetime import datetime
                claim_by_date = datetime.strptime(claim_by_date_str, '%Y-%m-%d').date()
            else:
                # Default to 30 days from now if no date provided
                claim_by_date = (now() + timedelta(days=30)).date()
            
            # Check if user still has enough points
            if claim_request.user.profile.points < claim_request.reward.cost:
                messages.error(request, f'User {claim_request.user.username} no longer has enough points.')
                return redirect('claim_requests')
            
            # Check if reward is still available
            if claim_request.reward.remaining_quantity() <= 0:
                messages.error(request, f'Reward "{claim_request.reward.name}" is out of stock.')
                return redirect('claim_requests')
            
            # Process the claim
            profile = claim_request.user.profile
            reward = claim_request.reward
            
            # Deduct points and update counts
            profile.points -= reward.cost
            profile.rewards_claimed += 1
            profile.save()
            
            reward.claimed_count += 1
            reward.save()
            
            # Update claim request with claim date
            claim_request.status = 'approved'
            claim_request.processed_at = now()
            claim_request.processed_by = request.user
            claim_request.claim_by_date = claim_by_date
            claim_request.save()
            
            messages.success(request, f'Claim request approved for {claim_request.user.username}. Reward must be claimed by {claim_by_date.strftime("%B %d, %Y")}.')
            
        except Exception as e:
            messages.error(request, f'Error processing request: {str(e)}')
    
    return redirect('claim_requests')


@login_required
def reject_claim_request(request, claim_id):
    """Reject a claim request"""
    if request.method == 'POST':
        try:
            claim_request = get_object_or_404(ClaimRequest, id=claim_id, status='pending')
            reason = request.POST.get('reason', '')
            
            # Update claim request
            claim_request.status = 'rejected'
            claim_request.processed_at = now()
            claim_request.processed_by = request.user
            claim_request.reason = reason
            claim_request.save()
            
            messages.success(request, f'Claim request rejected for {claim_request.user.username}.')
            
        except Exception as e:
            messages.error(request, f'Error processing request: {str(e)}')
    
    return redirect('claim_requests')


def add_reward(request):
    if request.method == 'POST':
        form = RewardForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('rewards')
    else:
        form = RewardForm()
    return render(request, 'accounts/reward_form.html', {'form': form})


def edit_reward(request, pk):
    reward = get_object_or_404(Reward, pk=pk)
    if request.method == 'POST':
        form = RewardForm(request.POST, request.FILES, instance=reward)
        if form.is_valid():
            form.save()
            return redirect('rewards')
    else:
        form = RewardForm(instance=reward)
    return render(request, 'accounts/reward_form.html', {'form': form})


def delete_reward(request, pk):
    reward = get_object_or_404(Reward, pk=pk)
    if request.method == 'POST':
        reward.delete()
        return redirect('rewards')
    return render(request, 'accounts/reward_confirm_delete.html', {'reward': reward})


def home_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'accounts/login.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # ✅ ADD THIS CHECK - Block mobile users from web login
            if hasattr(user, 'profile') and user.profile.signup_source == 'mobile':
                return render(request, 'accounts/login.html', {
                    'error': 'Mobile app users cannot access the web interface. Please use the mobile app.'
                })
            
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'accounts/login.html', {'error': 'Invalid username or password'})
    return render(request, 'accounts/login.html')


def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def dashboard_view(request):
    # ✅ Count only mobile app users
    total_users = User.objects.filter(profile__signup_source='mobile').count()
    
    # ✅ Get claim request statistics
    total_approved_claims = ClaimRequest.objects.filter(status='approved').count()
    total_denied_claims = ClaimRequest.objects.filter(status='rejected').count()
    total_pending_claims = ClaimRequest.objects.filter(status='pending').count()
    
    # Get processed requests for the recent activity section
    processed_requests = ClaimRequest.objects.filter(
        status__in=['approved', 'rejected']
    ).order_by('-processed_at')[:10]

    # ✅ Count only mobile app user registrations
    user_registrations = (
        User.objects.filter(profile__signup_source='mobile')
        .annotate(month=TruncMonth('date_joined'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )
    
    # Prepare graph data
    months = []
    counts = []
    for entry in user_registrations:
        months.append(entry['month'].strftime('%B'))
        counts.append(entry['count'])
    
    max_users = max(counts) if counts else 1
    
    # Generate SVG path data
    path_points = []
    for i, count in enumerate(counts):
        x = (i / (len(counts) - 1)) * 100 if len(counts) > 1 else 50
        y = 100 - (count / max_users) * 90
        path_points.append(f"L{x},{y}")
    
    users_graph_path = f"M{path_points[0][1:]}" + " ".join(path_points[1:]) if path_points else "M0,100 L100,100"
    
    context = {
        'total_users': total_users,
        'total_approved_claims': total_approved_claims,
        'total_denied_claims': total_denied_claims,
        'total_pending_claims': total_pending_claims,
        'processed_requests': processed_requests,
        'months': months,
        'counts': counts,
        'max_users': max_users,
        'users_graph_path': users_graph_path,
    }
    return render(request, 'accounts/dashboard.html', context)

def your_view(request):
    # Your existing view logic
    pending_requests_count = ClaimRequest.objects.filter(status='pending').count()
    
    context = {
        # Your existing context
        'pending_requests_count': pending_requests_count,
    }
    return render(request, 'your_template.html', context)

@login_required
def profile_view(request):
    user = request.user
    profile, _ = Profile.objects.get_or_create(user=user)
    password_form = PasswordChangeForm(user)
    password_updated = False

    if request.method == 'POST':
        if 'old_password' in request.POST:
            password_form = PasswordChangeForm(user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                password_updated = True
                messages.success(request, 'Your password was successfully updated!')
            else:
                messages.error(request, 'Please correct the error below.')
        else:
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.email = request.POST.get('email', user.email)
            profile.address = request.POST.get('address', profile.address)
            if 'profile_pic' in request.FILES:
                profile.profile_pic = request.FILES['profile_pic']
            user.save()
            profile.save()
            messages.success(request, 'Profile updated successfully!')

    return render(request, 'accounts/profile.html', {
        'user': user,
        'password_form': password_form,
        'password_updated': password_updated,
    })

@login_required
def users_view(request):
    search_query = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '').lower()

    # ✅ Only show mobile app users
    base_queryset = User.objects.filter(profile__signup_source='mobile').exclude(id=request.user.id)

    if search_query:
        base_queryset = base_queryset.filter(
            Q(username__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(profile__address__icontains=search_query)
        )

    filtered_users = []
    for user in base_queryset:
        last_active = user.profile.last_active
        is_active = False

        if last_active:
            seconds_since = (now() - last_active).total_seconds()
            is_active = seconds_since < 86400  # 24 hours

        user.is_active_status = is_active
        filtered_users.append(user)

    total_users = base_queryset.count()

    return render(request, 'accounts/users.html', {
        'users': filtered_users,
        'search_query': search_query,
        'total_users': total_users,  # Now only counts mobile users
    })

@csrf_exempt
@require_http_methods(["POST"])
def api_get_redemption_details(request):
    """Get details of a specific redemption by ID"""
    try:
        data = json.loads(request.body)
        redemption_id = data.get('redemption_id')
        
        if not redemption_id:
            return JsonResponse({'success': False, 'message': 'Redemption ID is required'}, status=400)
        
        claim_request = ClaimRequest.objects.get(id=redemption_id)
        
        redemption_data = {
            'id': claim_request.id,
            'user': {
                'id': claim_request.user.id,
                'username': claim_request.user.username,
                'full_name': claim_request.user.get_full_name(),
            },
            'reward': {
                'id': claim_request.reward.id,
                'name': claim_request.reward.name,
                'cost': claim_request.reward.cost,
            },
            'status': claim_request.status,
            'status_display': claim_request.get_status_display(),
            'requested_at': claim_request.requested_at.strftime('%Y-%m-%d %H:%M:%S'),
            'processed_at': claim_request.processed_at.strftime('%Y-%m-%d %H:%M:%S') if claim_request.processed_at else None,
            'processed_by': claim_request.processed_by.get_full_name() if claim_request.processed_by else None,
            'reason': claim_request.reason,
        }
        
        return JsonResponse({
            'success': True,
            'redemption': redemption_data
        })
        
    except ClaimRequest.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Redemption not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def api_get_claim_history(request):
    """Get claim history for a user in the mobile app"""
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        user = User.objects.get(id=user_id)
        
        # Get all claim requests for this user, ordered by most recent first
        claim_requests = ClaimRequest.objects.filter(user=user).order_by('-requested_at')
        
        history_data = []
        for claim in claim_requests:
            # Use timezone-aware formatting
            from django.utils.timezone import localtime
            
            history_data.append({
                'id': claim.id,
                'unique_id': claim.unique_id,
                'reward_name': claim.reward.name,
                'reward_cost': claim.reward.cost,
                'status': claim.status,
                'status_display': claim.get_status_display(),
                'requested_at': localtime(claim.requested_at).strftime('%Y-%m-%d %H:%M:%S'),
                'processed_at': localtime(claim.processed_at).strftime('%Y-%m-%d %H:%M:%S') if claim.processed_at else None,
                'claim_by_date': claim.claim_by_date.strftime('%Y-%m-%d') if claim.claim_by_date else None,
                'is_expired': claim.is_claim_expired(),
                'reason': claim.reason,
            })
        
        return JsonResponse({
            'success': True,
            'history': history_data
        })
        
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_login(request):
    try:
        data = json.loads(request.body)
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return JsonResponse({'success': False, 'message': 'Username and password are required'}, status=400)

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            # ✅ Update last_active timestamp
            profile = user.profile
            profile.last_active = now()
            profile.save(update_fields=['last_active'])

            # ✅ Prepare profile_pic URL
            request_host = request.get_host()
            protocol = 'https' if request.is_secure() else 'http'
            profile_pic_url = (
                f"{protocol}://{request_host}{profile.profile_pic.url}"
                if profile.profile_pic else None
            )

            return JsonResponse({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'profile_pic': profile_pic_url,
                    'points': profile.points,
                    'signup_source': profile.signup_source,
                    'last_active': profile.last_active,
                    'bottles_recycled': profile.bottles_recycled,
                    'rewards_claimed': profile.rewards_claimed,
                }
            }, status=200)
        else:
            return JsonResponse({'success': False, 'message': 'Invalid username or password'}, status=401)

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'An error occurred: {str(e)}'}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_update_profile(request):
    try:
        print("Raw request body:", request.body)  # Log raw incoming data
        
        data = json.loads(request.body)
        print("Parsed JSON data:", data)  # Log parsed data
        
        user_id = data.get('user_id')
        
        if not user_id:
            return JsonResponse({'success': False, 'message': 'User ID is required'}, status=400)
        
        user = User.objects.get(id=user_id)
        profile = user.profile
        
        # Log current data before update
        print("Current user data:", {
            'first_name': user.first_name,
            'last_name': user.last_name,
        })
        print("Current profile data:", {
            'address': profile.address,
            'phone_number': profile.phone_number,
            'birth_date': str(profile.birth_date)
        })
        
        # Update User model fields
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        
        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name
            
        user.save()
        
        # Update Profile model fields - explicitly handle None/empty values
        profile.address = data.get('address') or None
        profile.phone_number = data.get('phone_number') or None
        
        birth_date = data.get('birth_date')
        if birth_date:
            try:
                profile.birth_date = datetime.strptime(birth_date, '%Y-%m-%d').date()
            except ValueError as e:
                print(f"Date parsing error: {e}")
                profile.birth_date = None
        else:
            profile.birth_date = None
        
        # Save profile changes
        profile.save()
        
        # Log updated data
        print("Updated user data:", {
            'first_name': user.first_name,
            'last_name': user.last_name,
        })
        print("Updated profile data:", {
            'address': profile.address,
            'phone_number': profile.phone_number,
            'birth_date': str(profile.birth_date)
        })
        
        return JsonResponse({
            'success': True,
            'message': 'Profile updated successfully',
            'profile': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'address': profile.address,
                'phone_number': profile.phone_number,
                'birth_date': profile.birth_date.isoformat() if profile.birth_date else None,
                'profile_pic': request.build_absolute_uri(profile.profile_pic.url) if profile.profile_pic else None,
                'points': profile.points
            }
        })
        
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'}, status=404)
    except Exception as e:
        print(f"Error in api_update_profile: {str(e)}")
        return JsonResponse({'success': False, 'message': str(e)}, status=500)

    
@csrf_exempt
@require_http_methods(["POST"])
def api_signup(request):
    try:
        data = json.loads(request.body)
        required_fields = ['username', 'email', 'password', 'first_name', 'last_name']

        # ✅ Validate required fields
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({'success': False, 'message': f'{field.replace("_", " ").title()} is required'}, status=400)

        # ✅ Check if username/email already exists
        if User.objects.filter(username=data['username']).exists():
            return JsonResponse({'success': False, 'message': 'Username already exists'}, status=400)
        
        if User.objects.filter(email=data['email']).exists():
            return JsonResponse({'success': False, 'message': 'Email already exists'}, status=400)

        
        # Create user with all provided data
        user = User.objects.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            first_name=data['first_name'],
            last_name=data['last_name']
        )
        
        # Create profile with additional data
        profile = user.profile
        profile.address = data.get('address', '')
        profile.phone_number = data.get('phone_number', '')
        profile.signup_source = 'mobile'  # Set signup source for mobile users
        
        # Handle birth_date - convert string to date object
        birth_date_str = data.get('birth_date')
        if birth_date_str:
            try:
                profile.birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
            except ValueError:
                profile.birth_date = None
        else:
            profile.birth_date = None
            
        profile.save()
        
        # Prepare response data
        response_data = {
            'success': True,
            'message': 'Account created successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'address': profile.address,
                'phone_number': profile.phone_number,
                'birth_date': profile.birth_date.isoformat() if profile.birth_date else None,
                'profile_pic': profile.profile_pic.url if profile.profile_pic else None
            }
        }
        
        return JsonResponse(response_data, status=201)
    
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)


def forgot_password_view(request):
    message = ''
    if request.method == 'POST':
        email = request.POST.get('email')
        if User.objects.filter(email=email).exists():
            message = 'Password reset instructions have been sent to your email.'
            # send_mail('Reset Password', 'Here is the reset link...', settings.DEFAULT_FROM_EMAIL, [email])
        else:
            message = 'No account found with that email.'
    return render(request, 'accounts/forgot.html', {'message': message})


@csrf_exempt
def upload_profile_pic(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        profile_pic = request.FILES.get('profile_pic')

        if not user_id or not profile_pic:
            return JsonResponse({'success': False, 'message': 'Missing user_id or profile_pic'}, status=400)

        try:
            user = User.objects.get(id=user_id)
            user.profile.profile_pic = profile_pic
            user.profile.save()
            return JsonResponse({'success': True, 'profile_pic': user.profile.profile_pic.url})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)

    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)




from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
import json
from random import randint

# Temporary global variable to store the last count from IR sensor
# (In real deployment, you’d store this in a DB or Redis)
last_bottle_count = 0

@csrf_exempt
def api_receive_count(request):
    """Receives count from the IR sensor (ESP32 WROOM)."""
    global last_bottle_count
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8'))
            count = data.get("count", 0)
            last_bottle_count = int(count)
            print(f"Received bottle count: {last_bottle_count}")

            return JsonResponse({"success": True, "count": last_bottle_count})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=400)
    return JsonResponse({"success": False, "message": "Invalid method"}, status=405)


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from .models import Profile, BottleCount, User

@csrf_exempt
def update_bottle_count(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            count = data.get("count", 0)
            
            bottle_data, _ = BottleCount.objects.get_or_create(id=1)
            bottle_data.count = count
            bottle_data.last_updated = timezone.now()
            bottle_data.save()

            return JsonResponse({"success": True, "message": f"Updated bottle count = {count}"})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})
    return JsonResponse({"success": False, "message": "POST only"})


@csrf_exempt
def send_otp(request):
    try:
        if request.method != 'POST':
            return JsonResponse({'error': 'POST request required'}, status=400)

        # Read body once
        body_unicode = request.body.decode('utf-8')
        data = json.loads(body_unicode)

        email = data.get('email')
        if not email:
            return JsonResponse({'error': 'Email is required'}, status=400)

        code = str(randint(100000, 999999))

        # Mark previous OTPs as verified/used
        OTP.objects.filter(email=email, is_verified=False).update(is_verified=True)

        # Create new OTP
        otp = OTP.objects.create(email=email, code=code)
        print(f"📨 New OTP created for {email}: {code}")

        # Send email
        send_mail(
            'Your OTP Code',
            f'Your OTP is {code}. It expires in 10 minutes.',
            'your-email@gmail.com',  # <-- replace with settings.EMAIL_HOST_USER if you want
            [email],
            fail_silently=False
        )

        return JsonResponse({'message': f'OTP sent to {email}'})
    except Exception as e:
        print("❌ Error sending OTP:", e)
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def verify_otp(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        otp_code = str(data.get('otp')).strip()  # convert to string and remove spaces

        print(f"📩 Received email: {email}")
        print(f"🔢 Received OTP: {otp_code}")

        if not email or not otp_code:
            return JsonResponse({'error': 'Email and OTP are required'}, status=400)

        otps = OTP.objects.filter(email=email)
        print(f"📦 All OTPs for {email}: {[str(otp.code) for otp in otps]}")

        # Get latest unverified OTP and compare
        otp_entry = OTP.objects.filter(email=email, is_verified=False).order_by('-created_at').first()

        if not otp_entry or str(otp_entry.code).strip() != otp_code:
            print("❌ Invalid OTP entered.")
            return JsonResponse({'error': 'Invalid OTP'}, status=400)

        otp_entry.is_verified = True
        otp_entry.save()

        return JsonResponse({
            'success': True,
            'message': 'OTP verified successfully',
            'email': email
        }, status=200)

    except Exception as e:
        print("💥 Error verifying OTP:", str(e))
        return JsonResponse({'error': str(e)}, status=500)


    


@csrf_exempt
def scan_qr_code(request):
    if request.method == "POST":
        try:
            # Parse JSON from ESP32
            data = json.loads(request.body.decode("utf-8"))
            qr_data = json.loads(data.get("qr_data", "{}"))
            points = data.get("points", 0)

            username = qr_data.get("username")
            userId = qr_data.get("userId")

            # Find user by username
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return JsonResponse({"success": False, "error": "User not found"})

            # ✅ Update points (assuming you have a Profile model linked to User)
            if hasattr(user, "profile"):
                user.profile.points += int(points)
                user.profile.save()
                return JsonResponse({"success": True, "message": f"{points} points added to {username}."})
            else:
                return JsonResponse({"success": False, "error": "User profile not found"})

        except json.JSONDecodeError:
            return JsonResponse({"success": False, "error": "Invalid JSON"})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})
    else:
        return JsonResponse({"success": False, "error": "Invalid request method"})
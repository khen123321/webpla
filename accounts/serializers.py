from rest_framework import serializers
from .models import Reward
from django.contrib.auth.models import User
from .models import PasswordResetOTP
from rest_framework import serializers

class ForgotPasswordOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

# Serializer for verifying OTP and setting new password
class VerifyForgotPasswordOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8)

class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8)

    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User does not exist"})

        otp_obj = PasswordResetOTP.objects.filter(user=user, otp=data['otp']).last()
        print("🔍 Checking OTP:", data['otp'])
        print("📦 All OTPs for user:", list(PasswordResetOTP.objects.filter(user=user).values_list("otp", flat=True)))
        if not otp_obj:
            raise serializers.ValidationError({"otp": "Invalid OTP"})
        if otp_obj.is_expired():
            raise serializers.ValidationError({"otp": "OTP expired"})

        data['user'] = user
        return data

    def save(self):
        user = self.validated_data['user']
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        
class RewardSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reward
        fields = ['id', 'name', 'image', 'available', 'cost', 'total_quantity']  # remove claimed_count

from rest_framework import serializers
from .models import Reward

class RewardSerializer(serializers.ModelSerializer):
    remaining_quantity = serializers.SerializerMethodField()
    
    class Meta:
        model = Reward
        fields = ['id', 'name', 'image', 'available', 'cost', 'total_quantity', 'claimed_count', 'remaining_quantity']

    def get_remaining_quantity(self, obj):
        return obj.remaining_quantity()
    
from rest_framework import serializers
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    profile_pic = serializers.ImageField(required=False)

    class Meta:
        model = Profile
        fields = ['user', 'profile_pic']


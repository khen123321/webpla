from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.timezone import now
from django.conf import settings
import os
import uuid
from django.templatetags.static import static
from django.utils import timezone
from datetime import timedelta
import random

class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=10)

    
class EmailOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"{self.user.email} - {self.otp_code}"


class OTP(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=10)

    def __str__(self):
        return f"{self.email} - {self.code}"
    
class Reward(models.Model):
    name = models.CharField(max_length=255)
    image = models.ImageField(upload_to='reward_images/', null=True, blank=True)
    available = models.BooleanField(default=True)
    cost = models.IntegerField(default=0)
    total_quantity = models.IntegerField(default=0)
    claimed_count = models.IntegerField(default=0)

    def remaining_quantity(self):
        return max(self.total_quantity - self.claimed_count, 0)

    def availability_count(self):
        return f"{self.remaining_quantity()}/{self.total_quantity}"

    def __str__(self):
        return self.name


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_pic = models.ImageField(upload_to='profile_pics', null=True, blank=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    birth_date = models.DateField(blank=True, null=True)
    points = models.IntegerField(default=0)
    bottles_recycled = models.IntegerField(default=0)
    rewards_claimed = models.IntegerField(default=0)
    signup_source = models.CharField(max_length=20, default='web')
    last_active = models.DateTimeField(null=True, blank=True)
    
    def get_profile_pic_url(self):
        if self.profile_pic and hasattr(self.profile_pic, 'url'):
            return self.profile_pic.url
        return static('default.jpg')


    def __str__(self):
        return f"{self.user.username}'s Profile"


class ClaimRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='claim_requests')
    reward = models.ForeignKey(Reward, on_delete=models.CASCADE, related_name='claim_requests')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_claims')
    reason = models.TextField(blank=True, null=True, help_text="Reason for rejection (optional)")
    unique_id = models.CharField(max_length=10, unique=True, blank=True)
    claim_by_date = models.DateField(null=True, blank=True, help_text="Date by which the reward must be claimed")
    
    class Meta:
        ordering = ['-requested_at']
    
    def save(self, *args, **kwargs):
        if not self.unique_id:
            # Generate unique ID: CR + 6 random alphanumeric characters
            import random
            import string
            while True:
                random_chars = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                new_id = f"CR{random_chars}"
                if not ClaimRequest.objects.filter(unique_id=new_id).exists():
                    self.unique_id = new_id
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.unique_id} - {self.user.username} - {self.reward.name}"
    
    def is_claim_expired(self):
        """Check if the claim period has expired"""
        if self.claim_by_date and self.status == 'approved':
            from django.utils.timezone import now
            return now().date() > self.claim_by_date
        return False
    
    def can_approve(self):
        """Check if the claim can be approved (user has enough points and reward is available)"""
        return (self.status == 'pending' and 
                self.user.profile.points >= self.reward.cost and 
                self.reward.remaining_quantity() > 0)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()


class BottleCount(models.Model):
    count = models.IntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Bottle Count: {self.count}"

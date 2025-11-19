# forms.py (if you have one)
from django import forms
from .models import Reward

class RewardForm(forms.ModelForm):
    class Meta:
        model = Reward
        fields = ['name', 'image', 'available', 'cost', 'total_quantity']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'cost': forms.NumberInput(attrs={'class': 'form-control'}),
            'total_quantity': forms.NumberInput(attrs={'class': 'form-control'}),
            'available': forms.Select(choices=[(True, 'Yes'), (False, 'No')], attrs={'class': 'form-control'}),
        }
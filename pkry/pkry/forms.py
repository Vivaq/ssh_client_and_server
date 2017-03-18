from django import forms


class Command(forms.Form):
    field = forms.CharField(
        label=False,
        max_length=10000,
        widget=forms.Textarea,
    )

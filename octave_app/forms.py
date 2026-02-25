from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import (Assessment, ImpactCriteria, ImpactPriority,
                     InformationAsset, AssetContainer, ThreatScenario,
                     IMPACT_AREA_CHOICES, UserProfile)

W  = {'class': 'form-control'}
S  = {'class': 'form-select'}
TA = {'class': 'form-control', 'rows': 3}
TA2= {'class': 'form-control', 'rows': 2}


# ── MODULE 1: Auth Forms ──────────────────────────────────────

class RegisterForm(UserCreationForm):
    """
    Public registration — everyone joins as Auditee by default.
    Only Admin can later promote them to Auditor or change their role.
    """
    email        = forms.EmailField(required=True, widget=forms.EmailInput(attrs=W))
    first_name   = forms.CharField(required=True, widget=forms.TextInput(attrs=W))
    last_name    = forms.CharField(required=True, widget=forms.TextInput(attrs=W))
    organization = forms.CharField(required=False, widget=forms.TextInput(attrs=W))
    phone        = forms.CharField(required=False, widget=forms.TextInput(attrs=W))

    class Meta:
        model  = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for f in ['username', 'password1', 'password2']:
            self.fields[f].widget.attrs.update({'class': 'form-control'})
        self.fields['username'].help_text = None
        self.fields['password1'].help_text = None
        self.fields['password2'].help_text = None

    def clean_password1(self):
        password = self.cleaned_data.get("password1")
        if password:
            if not any(x.isupper() for x in password):
                raise forms.ValidationError("Password must contain at least one uppercase letter.")
            import re
            if not re.search(r"[@%$@!#%^&*()_+={}\[\]:;\"'<>,.?/|\\~`-]", password):
                raise forms.ValidationError("Password must contain at least one special character.")
        return password


class LoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': 'form-control', 'placeholder': 'Username'})
        self.fields['password'].widget.attrs.update({'class': 'form-control', 'placeholder': 'Password'})


class UserProfileForm(forms.ModelForm):
    """Used by Admin to edit any user's role/details, and by users to edit their own non-role fields."""
    first_name = forms.CharField(required=False, widget=forms.TextInput(attrs=W))
    last_name  = forms.CharField(required=False, widget=forms.TextInput(attrs=W))
    email      = forms.EmailField(required=False, widget=forms.EmailInput(attrs=W))

    class Meta:
        model  = UserProfile
        fields = ['role', 'organization', 'phone']
        widgets = {
            'role':         forms.Select(attrs=S),
            'organization': forms.TextInput(attrs=W),
            'phone':        forms.TextInput(attrs=W),
        }


class AssignAuditeeForm(forms.ModelForm):
    """Admin-only: assign an auditee (organisation staff) to an assessment."""
    class Meta:
        model   = Assessment
        fields  = ['assigned_auditee']
        widgets = {'assigned_auditee': forms.Select(attrs=S)}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assigned_auditee'].queryset    = User.objects.filter(profile__role='auditee')
        self.fields['assigned_auditee'].required    = False
        self.fields['assigned_auditee'].empty_label = '— Unassigned —'
        self.fields['assigned_auditee'].label       = 'Assign Auditee (Organisation Staff)'


class AssessmentForm(forms.ModelForm):
    """Auditor-only: create/edit an assessment. No auditee assignment — that's admin's job."""
    class Meta:
        model  = Assessment
        fields = ['title', 'organization', 'scope', 'assessor_name', 'assessor_email',
                  'start_date', 'end_date', 'status', 'notes']
        widgets = {
            'title':          forms.TextInput(attrs={**W, 'placeholder': 'e.g. 2025 Risk Assessment'}),
            'organization':   forms.TextInput(attrs=W),
            'scope':          forms.Textarea(attrs={**TA, 'placeholder': 'Define scope, systems, boundaries…'}),
            'assessor_name':  forms.TextInput(attrs=W),
            'assessor_email': forms.EmailInput(attrs=W),
            'start_date':     forms.DateInput(attrs={**W, 'type': 'date'}),
            'end_date':       forms.DateInput(attrs={**W, 'type': 'date'}),
            'status':         forms.Select(attrs=S),
            'notes':          forms.Textarea(attrs=TA2),
        }


class ImpactCriteriaForm(forms.ModelForm):
    class Meta:
        model  = ImpactCriteria
        fields = ['impact_area','area_label','criterion','low_criteria','mod_criteria','high_criteria']
        widgets = {
            'impact_area':   forms.Select(attrs=S),
            'area_label':    forms.TextInput(attrs={**W,'placeholder':'Only if "User-Defined"'}),
            'criterion':     forms.TextInput(attrs={**W,'placeholder':'e.g. Revenue Loss, Customer Loss…'}),
            'low_criteria':  forms.Textarea(attrs={**TA,'placeholder':'Describe LOW impact condition…'}),
            'mod_criteria':  forms.Textarea(attrs={**TA,'placeholder':'Describe MODERATE impact condition…'}),
            'high_criteria': forms.Textarea(attrs={**TA,'placeholder':'Describe HIGH impact condition…'}),
        }
        labels = {
            'low_criteria': 'Low Impact Criteria',
            'mod_criteria': 'Moderate Impact Criteria',
            'high_criteria':'High Impact Criteria',
        }


class ImpactPriorityForm(forms.Form):
    def __init__(self, *args, assessment=None, **kwargs):
        super().__init__(*args, **kwargs)
        if assessment:
            areas = assessment.impact_criteria.values_list('impact_area','area_label').distinct()
            seen  = set()
            for area, label in areas:
                if area in seen:
                    continue
                seen.add(area)
                display = label if area == 'custom' and label else dict(IMPACT_AREA_CHOICES).get(area, area)
                self.fields[f'rank_{area}'] = forms.ChoiceField(
                    label=f'Priority Rank — {display}',
                    choices=[(i, str(i)) for i in range(1, 6)],
                    widget=forms.Select(attrs=S),
                    help_text='5 = most important to your organisation, 1 = least important.',
                )


class InformationAssetForm(forms.ModelForm):
    class Meta:
        model  = InformationAsset
        fields = ['name','description','rationale','owner','owner_type',
                  'req_confidentiality','req_integrity','req_availability',
                  'most_important_req','notes']
        widgets = {
            'name':                forms.TextInput(attrs={**W,'placeholder':'Asset name'}),
            'description':         forms.Textarea(attrs={**TA,'placeholder':'What is this asset?'}),
            'rationale':           forms.Textarea(attrs={**TA,'placeholder':'Why is this asset critical?'}),
            'owner':               forms.TextInput(attrs={**W,'placeholder':'Responsible person or team'}),
            'owner_type':          forms.Select(attrs=S),
            'req_confidentiality': forms.Textarea(attrs={**TA,'placeholder':'Who should have access? What happens if disclosed?'}),
            'req_integrity':       forms.Textarea(attrs={**TA,'placeholder':'Accuracy requirements? Impact of unauthorised modification?'}),
            'req_availability':    forms.Textarea(attrs={**TA,'placeholder':'How available must it be? Impact of downtime?'}),
            'most_important_req':  forms.Select(attrs=S),
            'notes':               forms.Textarea(attrs=TA2),
        }
        labels = {
            'req_confidentiality': 'Confidentiality Requirement',
            'req_integrity':       'Integrity Requirement',
            'req_availability':    'Availability Requirement',
            'most_important_req':  'Most Important Security Requirement',
        }


class AssetContainerForm(forms.ModelForm):
    class Meta:
        model  = AssetContainer
        fields = ['container_type','name','description','location','owner','is_critical','notes']
        widgets = {
            'container_type': forms.Select(attrs=S),
            'name':           forms.TextInput(attrs={**W,'placeholder':'Container name (e.g. Email Server, HR Staff)'}),
            'description':    forms.Textarea(attrs={**TA,'placeholder':'How is the asset stored/transported/processed here?'}),
            'location':       forms.TextInput(attrs={**W,'placeholder':'Physical or network location'}),
            'owner':          forms.TextInput(attrs={**W,'placeholder':'Who manages this container?'}),
            'is_critical':    forms.CheckboxInput(attrs={'class':'form-check-input'}),
            'notes':          forms.Textarea(attrs=TA2),
        }


class ThreatScenarioForm(forms.ModelForm):
    class Meta:
        model  = ThreatScenario
        fields = [
            'container','area_of_concern',
            'scenario_name',
            'actor','means','motive','outcome','access_path','probability','consequences',
            'impact_area','impact_value','impact_rationale',
            'mitigation_strategy','mitigation_plan','mitigation_rationale',
            'responsible_party','target_date','mitigation_status',
            'notes',
        ]
        widgets = {
            'container':             forms.Select(attrs=S),
            'area_of_concern':       forms.Textarea(attrs={**TA,'placeholder':'Describe the area of concern…'}),
            'scenario_name':         forms.TextInput(attrs={**W,'placeholder':'Short threat name'}),
            'actor':                 forms.Textarea(attrs={**TA2,'placeholder':'Who would cause this threat?'}),
            'means':                 forms.Textarea(attrs={**TA2,'placeholder':'What tools/methods would they use?'}),
            'motive':                forms.Textarea(attrs={**TA2,'placeholder':'What is their reason?'}),
            'outcome':               forms.Textarea(attrs={**TA2,'placeholder':'Disclosure / Modification / Destruction / Interruption?'}),
            'access_path':           forms.Textarea(attrs={**TA2,'placeholder':'How would they access the asset?'}),
            'probability':           forms.Select(attrs=S),
            'consequences':          forms.Textarea(attrs={**TA,'placeholder':'Consequences if this threat is realised?'}),
            'impact_area':           forms.Select(attrs=S),
            'impact_value':          forms.Select(attrs=S),
            'impact_rationale':      forms.Textarea(attrs={**TA2,'placeholder':'Why did you choose this impact level?'}),
            'mitigation_strategy':   forms.Select(attrs=S),
            'mitigation_plan':       forms.Textarea(attrs={**TA,'placeholder':'What will be done to address this risk?'}),
            'mitigation_rationale':  forms.Textarea(attrs={**TA2,'placeholder':'Why this strategy?'}),
            'responsible_party':     forms.TextInput(attrs=W),
            'target_date':           forms.DateInput(attrs={**W,'type':'date'}),
            'mitigation_status':     forms.Select(attrs=S),
            'notes':                 forms.Textarea(attrs=TA2),
        }

    def __init__(self, *args, asset=None, **kwargs):
        super().__init__(*args, **kwargs)
        if asset:
            self.fields['container'].queryset = AssetContainer.objects.filter(asset=asset)
            self.fields['container'].required = False

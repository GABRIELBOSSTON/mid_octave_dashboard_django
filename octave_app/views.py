from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.utils import timezone
from functools import wraps

from .models import (Assessment, ImpactCriteria, ImpactPriority,
                     InformationAsset, AssetContainer, ThreatScenario,
                     IMPACT_AREA_CHOICES, UserProfile)
from .forms  import (AssessmentForm, ImpactCriteriaForm, ImpactPriorityForm,
                     InformationAssetForm, AssetContainerForm, ThreatScenarioForm,
                     RegisterForm, LoginForm, UserProfileForm, AssignAuditeeForm)


# ── Role Decorators ──────────────────────────────────────────

def auditor_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        try:
            if request.user.profile.role != 'auditor':
                messages.error(request, 'Access denied. Only Auditors can perform this action.')
                return redirect('dashboard')
        except UserProfile.DoesNotExist:
            messages.error(request, 'No profile found.')
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper

def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        try:
            if request.user.profile.role != 'admin':
                messages.error(request, 'Access denied. Admin role required.')
                return redirect('dashboard')
        except UserProfile.DoesNotExist:
            messages.error(request, 'No profile found.')
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper


# ────────────────────────────────────────────────────────────
# MODULE 1 — AUTH VIEWS
# ────────────────────────────────────────────────────────────

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    form = LoginForm(request, data=request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.get_user()
        login(request, user)
        messages.success(request, f'Welcome back, {user.first_name or user.username}!')
        return redirect('dashboard')
    return render(request, 'octave_app/auth/login.html', {'form': form})


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    form = RegisterForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        user.first_name = form.cleaned_data['first_name']
        user.last_name  = form.cleaned_data['last_name']
        user.email      = form.cleaned_data['email']
        user.save()
        UserProfile.objects.get_or_create(
        user=user,
        defaults={
            'role': 'auditee',
            'organization': form.cleaned_data.get('organization') or '',
            'phone': form.cleaned_data.get('phone') or '',
            }
        )
        # login(request, user)  # Removed as per request to redirect to login instead
        messages.success(request, f'Account created successfully! Welcome, {user.first_name}. Please log in to continue.')
        return redirect('login')
    return render(request, 'octave_app/auth/register.html', {'form': form})


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('login')


@login_required
@admin_required
def user_list(request):
    users = User.objects.select_related('profile').all().order_by('-date_joined')
    return render(request, 'octave_app/auth/user_list.html', {'users': users})


@login_required
@admin_required
def user_edit(request, user_pk):
    target_user = get_object_or_404(User, pk=user_pk)
    profile, _  = UserProfile.objects.get_or_create(user=target_user)
    form = UserProfileForm(request.POST or None, instance=profile,
                           initial={'first_name': target_user.first_name,
                                    'last_name':  target_user.last_name,
                                    'email':      target_user.email})
    if form.is_valid():
        target_user.first_name = form.cleaned_data['first_name']
        target_user.last_name  = form.cleaned_data['last_name']
        target_user.email      = form.cleaned_data['email']
        target_user.save()
        form.save()
        messages.success(request, f'User {target_user.username} updated.')
        return redirect('user_list')
    return render(request, 'octave_app/auth/user_edit.html',
                  {'form': form, 'target_user': target_user})


@login_required
@admin_required
def user_delete(request, user_pk):
    target_user = get_object_or_404(User, pk=user_pk)
    if target_user == request.user:
        messages.error(request, 'You cannot delete your own account.')
        return redirect('user_list')
    if request.method == 'POST':
        target_user.delete()
        messages.success(request, 'User deleted.')
        return redirect('user_list')
    return render(request, 'octave_app/confirm_delete.html',
                  {'object': target_user, 'type': 'User Account'})


@login_required
@admin_required
def assign_auditee(request, pk):
    """Admin-only: assign an auditee to an assessment."""
    a    = get_object_or_404(Assessment, pk=pk)
    form = AssignAuditeeForm(request.POST or None, instance=a)
    if form.is_valid():
        form.save()
        auditee = form.cleaned_data['assigned_auditee']
        if auditee:
            messages.success(request, f'Assessment assigned to {auditee.get_full_name() or auditee.username}.')
        else:
            messages.success(request, 'Auditee assignment removed.')
        return redirect('assessment_detail', pk=pk)
    return render(request, 'octave_app/assign_auditee.html', {
        'form': form, 'assessment': a,
    })


@login_required
def profile_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    form = UserProfileForm(request.POST or None, instance=profile,
                           initial={'first_name': request.user.first_name,
                                    'last_name':  request.user.last_name,
                                    'email':      request.user.email})
    if request.method == 'POST' and form.is_valid():
        request.user.first_name = form.cleaned_data['first_name']
        request.user.last_name  = form.cleaned_data['last_name']
        request.user.email      = form.cleaned_data['email']
        request.user.save()
        # Only admin can change their own role
        if not profile.is_admin():
            form.instance.role = profile.role
        form.save()
        messages.success(request, 'Profile updated.')
        return redirect('profile')
    return render(request, 'octave_app/auth/profile.html', {'form': form, 'profile': profile})


# ────────────────────────────────────────────────────────────
# DASHBOARD
# ────────────────────────────────────────────────────────────

@login_required
def dashboard(request):
    user = request.user
    if user.is_superuser:
        profile, created = UserProfile.objects.get_or_create(user=user)
        if profile.role != 'admin':
            profile.role = 'admin'
            profile.save()
        role = 'admin'
    else:
        try:
            role = user.profile.role
        except UserProfile.DoesNotExist:
            role = 'auditee'

    if role == 'admin':
        assessments = Assessment.objects.all()
    elif role == 'auditor':
        assessments = Assessment.objects.filter(owner=user)
    else:  # auditee
        assessments = Assessment.objects.filter(assigned_auditee=user)

    all_threats = ThreatScenario.objects.filter(asset__assessment__in=assessments)
    risk_counts = {'high': 0, 'medium': 0, 'low': 0, 'unscored': 0}
    for t in all_threats:
        lvl = t.compute_risk_score()['level']
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    # Admin-specific: user breakdown
    admin_count   = 0
    auditor_count = 0
    auditee_count = 0
    total_users   = 0
    if role == 'admin':
        from .models import UserProfile as UP
        admin_count   = UP.objects.filter(role='admin').count()
        auditor_count = UP.objects.filter(role='auditor').count()
        auditee_count = UP.objects.filter(role='auditee').count()
        total_users   = User.objects.count()

    context = {
        'assessments':       assessments,
        'total_assessments': assessments.count(),
        'total_assets':      InformationAsset.objects.filter(assessment__in=assessments).count(),
        'total_threats':     all_threats.count(),
        'risk_counts':       risk_counts,
        'recent':            assessments[:5],
        'user_role':         role,
        # admin extras
        'total_users':       total_users,
        'admin_count':       admin_count,
        'auditor_count':     auditor_count,
        'auditee_count':     auditee_count,
    }
    return render(request, 'octave_app/dashboard.html', context)


# ────────────────────────────────────────────────────────────
# ASSESSMENT CRUD
# ────────────────────────────────────────────────────────────

@login_required
def assessment_list(request):
    user = request.user
    try:
        role = user.profile.role
    except UserProfile.DoesNotExist:
        role = 'auditee'
    if role == 'admin':
        assessments = Assessment.objects.all()
    elif role == 'auditor':
        assessments = Assessment.objects.filter(owner=user)
    else:
        assessments = Assessment.objects.filter(assigned_auditee=user)
    return render(request, 'octave_app/assessment_list.html',
                  {'assessments': assessments})

@login_required
@auditor_required
def assessment_create(request):
    form = AssessmentForm(request.POST or None)
    if form.is_valid():
        obj = form.save(commit=False)
        obj.owner = request.user
        obj.save()
        messages.success(request, f'Assessment "{obj.title}" created. Now complete Step 1.')
        return redirect('step1_criteria', pk=obj.pk)
    return render(request, 'octave_app/assessment_form.html',
                  {'form': form, 'page_title': 'New Assessment', 'btn': 'Create'})

@login_required
def assessment_detail(request, pk):
    a = get_object_or_404(Assessment, pk=pk)
    assets = a.assets.prefetch_related('threats', 'containers').all()
    threats = a.get_all_threats()
    scored  = [t for t in threats if t.impact_value]
    risk_scores = sorted(
        [{'threat': t, **t.compute_risk_score()} for t in scored],
        key=lambda x: -x['total']
    )
    from django.urls import reverse
    steps_progress = [
        ('Step 1: Criteria',   a.is_step1_complete(), reverse('step1_criteria', args=[pk])),
        ('Step 2: Assets',     a.is_step2_complete(), reverse('step2_asset_add', args=[pk])),
        ('Step 3: Containers', a.is_step3_complete(), reverse('assessment_detail', args=[pk])),
        ('Steps 4-8: Threats', a.is_step5_complete(), reverse('assessment_detail', args=[pk])),
        ('Step 7: Scored',     a.is_step7_complete(), reverse('assessment_detail', args=[pk])),
        ('Step 8: Mitigated',  a.is_step8_complete(), reverse('generate_report',  args=[pk])),
    ]
    return render(request, 'octave_app/assessment_detail.html', {
        'assessment':    a,
        'assets':        assets,
        'risk_scores':   risk_scores,
        'risk_summary':  a.get_risk_summary(),
        'steps_progress': steps_progress,
    })

@login_required
@auditor_required
def assessment_update(request, pk):
    a = get_object_or_404(Assessment, pk=pk, owner=request.user)
    form = AssessmentForm(request.POST or None, instance=a)
    if form.is_valid():
        form.save()
        messages.success(request, 'Assessment updated.')
        return redirect('assessment_detail', pk=pk)
    return render(request, 'octave_app/assessment_form.html',
                  {'form': form, 'page_title': 'Edit Assessment', 'btn': 'Save', 'assessment': a})

@login_required
@auditor_required
def assessment_delete(request, pk):
    a = get_object_or_404(Assessment, pk=pk)
    if request.method == 'POST':
        a.delete()
        messages.success(request, 'Assessment deleted.')
        return redirect('assessment_list')
    return render(request, 'octave_app/confirm_delete.html',
                  {'object': a, 'type': 'Assessment'})


# ────────────────────────────────────────────────────────────
# STEP 1 — WS-1 to WS-7  (Impact Criteria + Prioritization)
# ────────────────────────────────────────────────────────────

@login_required
def step1_criteria(request, pk):
    """List all impact criteria and the priority ranking for this assessment."""
    a       = get_object_or_404(Assessment, pk=pk)
    criteria= a.impact_criteria.order_by('impact_area', 'criterion')
    priorities = a.impact_priorities.order_by('-priority_rank')
    # group criteria by area for display
    grouped = {}
    for c in criteria:
        key = c.get_area_display_name()
        grouped.setdefault(key, []).append(c)
    return render(request, 'octave_app/step1_criteria.html', {
        'assessment': a,
        'grouped':    grouped,
        'priorities': priorities,
    })


@login_required
@auditor_required
def step1_criteria_add(request, pk):
    a    = get_object_or_404(Assessment, pk=pk)
    form = ImpactCriteriaForm(request.POST or None)
    if form.is_valid():
        obj = form.save(commit=False)
        obj.assessment = a
        obj.save()
        messages.success(request, 'Criterion added.')
        return redirect('step1_criteria', pk=pk)
    return render(request, 'octave_app/criteria_form.html', {
        'form': form, 'assessment': a,
        'page_title': 'Add Impact Criterion (WS-1 to WS-6)', 'btn': 'Add',
    })


@login_required
@auditor_required
def step1_criteria_edit(request, pk, crit_pk):
    a    = get_object_or_404(Assessment, pk=pk)
    crit = get_object_or_404(ImpactCriteria, pk=crit_pk, assessment=a)
    form = ImpactCriteriaForm(request.POST or None, instance=crit)
    if form.is_valid():
        form.save()
        messages.success(request, 'Criterion updated.')
        return redirect('step1_criteria', pk=pk)
    return render(request, 'octave_app/criteria_form.html', {
        'form': form, 'assessment': a,
        'page_title': 'Edit Impact Criterion', 'btn': 'Save',
    })


@login_required
@auditor_required
def step1_criteria_delete(request, pk, crit_pk):
    a    = get_object_or_404(Assessment, pk=pk)
    crit = get_object_or_404(ImpactCriteria, pk=crit_pk, assessment=a)
    if request.method == 'POST':
        crit.delete()
        messages.success(request, 'Criterion deleted.')
        return redirect('step1_criteria', pk=pk)
    return render(request, 'octave_app/confirm_delete.html',
                  {'object': crit, 'type': 'Impact Criterion'})


@login_required
@auditor_required
def step1_prioritize(request, pk):
    """WS-7: Set priority rank for each active impact area."""
    a = get_object_or_404(Assessment, pk=pk)
    if not a.impact_criteria.exists():
        messages.warning(request, 'Add at least one impact criterion first.')
        return redirect('step1_criteria', pk=pk)
    form = ImpactPriorityForm(request.POST or None, assessment=a)
    if form.is_valid():
        # Rebuild priorities from form
        a.impact_priorities.all().delete()
        seen_ranks = set()
        errors = []
        for field_name, value in form.cleaned_data.items():
            area = field_name.replace('rank_', '', 1)
            rank = int(value)
            if rank in seen_ranks:
                errors.append(f'Rank {rank} is used more than once. Each rank must be unique.')
                break
            seen_ranks.add(rank)
            # get label if custom
            crit = a.impact_criteria.filter(impact_area=area).first()
            label = crit.area_label if crit else ''
            ImpactPriority.objects.create(
                assessment=a, impact_area=area,
                area_label=label, priority_rank=rank
            )
        if errors:
            for e in errors:
                messages.error(request, e)
            a.impact_priorities.all().delete()
        else:
            messages.success(request, 'Impact area priorities saved (WS-7).')
            return redirect('step1_criteria', pk=pk)
    return render(request, 'octave_app/step1_prioritize.html', {
        'form': form, 'assessment': a,
    })


# ────────────────────────────────────────────────────────────
# STEP 2 — WS-8  (Information Asset Profile)
# ────────────────────────────────────────────────────────────


@login_required
@auditor_required
def step2_asset_add(request, pk):
    a    = get_object_or_404(Assessment, pk=pk)
    form = InformationAssetForm(request.POST or None)
    if form.is_valid():
        asset = form.save(commit=False)
        asset.assessment = a
        asset.save()
        messages.success(request, f'Asset "{asset.name}" added.')
        return redirect('step3_containers', asset_pk=asset.pk)
    return render(request, 'octave_app/asset_form.html', {
        'form': form, 'assessment': a,
        'page_title': 'Add Information Asset (WS-8)', 'btn': 'Save & Go to Step 3',
    })


@login_required
@auditor_required
def step2_asset_edit(request, asset_pk):
    asset = get_object_or_404(InformationAsset, pk=asset_pk)
    form  = InformationAssetForm(request.POST or None, instance=asset)
    if form.is_valid():
        form.save()
        messages.success(request, 'Asset updated.')
        return redirect('assessment_detail', pk=asset.assessment.pk)
    return render(request, 'octave_app/asset_form.html', {
        'form': form, 'assessment': asset.assessment,
        'page_title': 'Edit Asset (WS-8)', 'btn': 'Save',
    })


@login_required
@auditor_required
def step2_asset_delete(request, asset_pk):
    asset = get_object_or_404(InformationAsset, pk=asset_pk)
    apk   = asset.assessment.pk
    if request.method == 'POST':
        asset.delete()
        messages.success(request, 'Asset deleted.')
        return redirect('assessment_detail', pk=apk)
    return render(request, 'octave_app/confirm_delete.html',
                  {'object': asset, 'type': 'Information Asset'})


# ────────────────────────────────────────────────────────────
# STEP 3 — WS-9  (Asset Containers / Risk Environment Map)
# ────────────────────────────────────────────────────────────


@login_required
def step3_containers(request, asset_pk):
    asset      = get_object_or_404(InformationAsset, pk=asset_pk)
    containers = asset.containers.all()
    container_guide = [
        ('internal_technical', 'Internal Technical', 'Servers, databases, applications inside the org', '#eff6ff'),
        ('external_technical', 'External Technical', 'Cloud, third-party, vendor systems', '#f0fdfa'),
        ('physical',           'Physical',           'Paper files, offices, storage, portable devices', '#fffbeb'),
        ('people',             'People',             'Staff who store/carry this information as knowledge', '#fdf4ff'),
    ]
    return render(request, 'octave_app/step3_containers.html', {
        'asset': asset, 'containers': containers, 'container_guide': container_guide,
    })


@login_required
@auditor_required
def step3_container_add(request, asset_pk):
    asset = get_object_or_404(InformationAsset, pk=asset_pk)
    form  = AssetContainerForm(request.POST or None)
    if form.is_valid():
        c = form.save(commit=False)
        c.asset = asset
        c.save()
        messages.success(request, f'Container "{c.name}" added.')
        return redirect('step3_containers', asset_pk=asset_pk)
    return render(request, 'octave_app/container_form.html', {
        'form': form, 'asset': asset,
        'page_title': 'Add Container (WS-9)', 'btn': 'Add Container',
    })


@login_required
@auditor_required
def step3_container_edit(request, container_pk):
    c    = get_object_or_404(AssetContainer, pk=container_pk)
    form = AssetContainerForm(request.POST or None, instance=c)
    if form.is_valid():
        form.save()
        messages.success(request, 'Container updated.')
        return redirect('step3_containers', asset_pk=c.asset.pk)
    return render(request, 'octave_app/container_form.html', {
        'form': form, 'asset': c.asset,
        'page_title': 'Edit Container', 'btn': 'Save',
    })


@login_required
@auditor_required
def step3_container_delete(request, container_pk):
    c       = get_object_or_404(AssetContainer, pk=container_pk)
    asset_pk= c.asset.pk
    if request.method == 'POST':
        c.delete()
        messages.success(request, 'Container deleted.')
        return redirect('step3_containers', asset_pk=asset_pk)
    return render(request, 'octave_app/confirm_delete.html',
                  {'object': c, 'type': 'Container'})


# ────────────────────────────────────────────────────────────
# STEPS 4-8 — WS-10  (Threat Scenario / Risk Worksheet)
# ────────────────────────────────────────────────────────────


def _threat_extra_ctx(asset):
    import json
    priorities = asset.assessment.get_impact_priorities()
    criteria   = asset.assessment.impact_criteria.order_by('impact_area', 'criterion')
    by_area    = {}
    for c in criteria:
        key = c.get_area_display_name()
        by_area.setdefault(key, []).append(c)
    return {
        'priorities':       priorities,
        'priorities_json':  json.dumps(priorities),
        'criteria_by_area': by_area,
    }


@login_required
@auditor_required
def step4_threat_add(request, asset_pk):
    asset = get_object_or_404(InformationAsset, pk=asset_pk)
    form  = ThreatScenarioForm(request.POST or None, asset=asset)
    if form.is_valid():
        t = form.save(commit=False)
        t.asset = asset
        t.save()
        messages.success(request, 'Threat scenario saved.')
        return redirect('assessment_detail', pk=asset.assessment.pk)
    ctx = {'form': form, 'asset': asset,
           'page_title': 'Add Threat Scenario (WS-10)', 'btn': 'Save Scenario'}
    ctx.update(_threat_extra_ctx(asset))
    return render(request, 'octave_app/threat_form.html', ctx)


@login_required
@auditor_required
def step4_threat_edit(request, threat_pk):
    t    = get_object_or_404(ThreatScenario, pk=threat_pk)
    form = ThreatScenarioForm(request.POST or None, instance=t, asset=t.asset)
    if form.is_valid():
        form.save()
        messages.success(request, 'Threat scenario updated.')
        return redirect('assessment_detail', pk=t.asset.assessment.pk)
    ctx = {'form': form, 'asset': t.asset,
           'page_title': 'Edit Threat Scenario', 'btn': 'Save Changes',
           'score': t.compute_risk_score()}
    ctx.update(_threat_extra_ctx(t.asset))
    return render(request, 'octave_app/threat_form.html', ctx)


@login_required
@auditor_required
def step4_threat_delete(request, threat_pk):
    t   = get_object_or_404(ThreatScenario, pk=threat_pk)
    apk = t.asset.assessment.pk
    if request.method == 'POST':
        t.delete()
        messages.success(request, 'Threat deleted.')
        return redirect('assessment_detail', pk=apk)
    return render(request, 'octave_app/confirm_delete.html',
                  {'object': t, 'type': 'Threat Scenario'})


# ────────────────────────────────────────────────────────────
# REPORT GENERATION
# ────────────────────────────────────────────────────────────



@login_required
def generate_report(request, pk):
    a           = get_object_or_404(Assessment, pk=pk)
    assets      = a.assets.prefetch_related('threats', 'containers').all()
    criteria    = a.impact_criteria.order_by('impact_area', 'criterion')
    priorities  = a.impact_priorities.order_by('-priority_rank')
    all_threats = a.get_all_threats().select_related('asset', 'container')

    # Score every threat and sort by risk (high first)
    scored_threats = sorted(
        [{'threat': t, **t.compute_risk_score()} for t in all_threats],
        key=lambda x: -x['total']
    )

    # Group criteria by area for WS-1 to WS-6 display
    criteria_grouped = {}
    for c in criteria:
        key = c.get_area_display_name()
        criteria_grouped.setdefault(key, []).append(c)

    # Summary counts
    risk_summary = {'high': 0, 'medium': 0, 'low': 0, 'unscored': 0}
    for s in scored_threats:
        risk_summary[s['level']] = risk_summary.get(s['level'], 0) + 1

    # --- MODULE 11: Compute compliance score from mitigation status ---
    total_threats  = len(scored_threats)
    mitigated      = sum(1 for s in scored_threats if s['threat'].mitigation_strategy)
    compliance_pct = int((mitigated / total_threats * 100)) if total_threats else 0
    if compliance_pct >= 85:
        compliance_label = 'Compliant'
        compliance_color = 'success'
    elif compliance_pct >= 60:
        compliance_label = 'Needs Improvement'
        compliance_color = 'warning'
    else:
        compliance_label = 'Non-Compliant'
        compliance_color = 'danger'

    # --- Final Audit Opinion ---
    high_count = risk_summary['high']
    med_count  = risk_summary['medium']
    if high_count == 0 and med_count <= 2:
        final_opinion       = 'Secure'
        final_opinion_color = 'success'
        final_opinion_icon  = 'shield-check'
    elif high_count <= 2:
        final_opinion       = 'Acceptable Risk'
        final_opinion_color = 'warning'
        final_opinion_icon  = 'shield-exclamation'
    else:
        final_opinion       = 'Needs Immediate Action'
        final_opinion_color = 'danger'
        final_opinion_icon  = 'shield-x'

    # --- Audit Findings (auto-generated for high/medium risks without mitigation) ---
    findings = []
    for s in scored_threats:
        t = s['threat']
        if s['level'] in ('high', 'medium') and not t.mitigation_plan:
            findings.append({
                'issue':          t.scenario_name,
                'risk_level':     s['level'],
                'risk_score':     s['total'],
                'affected_asset': t.asset.name,
                'area_of_concern':t.area_of_concern,
                'consequences':   t.consequences,
                'recommendation': f'Implement controls to address: {t.means}. Consider mitigation strategy for this {s["level"]}-risk scenario.',
            })

    # --- AI Recommendations placeholder (real AI via Module 10 if integrated) ---
    ai_recommendations = []
    if risk_summary['high'] > 0:
        ai_recommendations.append('Prioritize immediate remediation of HIGH risk threats. Assign responsible parties and set target dates within 30 days.')
    if risk_summary['medium'] > 0:
        ai_recommendations.append('Schedule medium-risk mitigations within 90 days. Consider risk transfer for threats outside direct control.')
    if compliance_pct < 60:
        ai_recommendations.append('Compliance score is critical. Conduct an urgent review of all unmitigated threats and implement a formal risk treatment plan.')
    if not ai_recommendations:
        ai_recommendations.append('Risk posture is acceptable. Continue monitoring and review assessment quarterly.')

    context = {
        'assessment':        a,
        'assets':            assets,
        'criteria_grouped':  criteria_grouped,
        'priorities':        priorities,
        'scored_threats':    scored_threats,
        'risk_summary':      risk_summary,
        'report_date':       timezone.now(),
        # Module 11 fields
        'compliance_pct':    compliance_pct,
        'compliance_label':  compliance_label,
        'compliance_color':  compliance_color,
        'final_opinion':     final_opinion,
        'final_opinion_color': final_opinion_color,
        'final_opinion_icon':  final_opinion_icon,
        'findings':          findings,
        'ai_recommendations':ai_recommendations,
        'mitigated_count':   mitigated,
        'total_threats_count': total_threats,
    }
    return render(request, 'octave_app/report.html', context)


"""
Models strictly mapped to OCTAVE Allegro Worksheets v1.0

WS-1  → ImpactCriteria  (Reputation)
WS-2  → ImpactCriteria  (Financial)
WS-3  → ImpactCriteria  (Productivity)
WS-4  → ImpactCriteria  (Safety & Health)
WS-5  → ImpactCriteria  (Fines & Legal Penalties)
WS-6  → ImpactCriteria  (User-Defined, optional)
WS-7  → ImpactPriority  (rank 1-5 per area)
WS-8  → InformationAsset (profile)
WS-9  → AssetContainer  (internal/external × technical/physical/people)
WS-10 → ThreatScenario  (actor, means, motive, outcome, access, probability, consequences + risk score)
"""

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


# ══════════════════════════════════════════════════════════════
# MODULE 1 — USER PROFILE (Role-Based Access Control)
# ══════════════════════════════════════════════════════════════

class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('admin',   'Admin'),
        ('auditor', 'Auditor'),
        ('auditee', 'Auditee'),
    ]
    user         = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role         = models.CharField(max_length=10, choices=ROLE_CHOICES, default='auditee')
    organization = models.CharField(max_length=255, blank=True)
    phone        = models.CharField(max_length=30, blank=True)
    created_at   = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'{self.user.username} ({self.get_role_display()})'

    def is_admin(self):
        return self.role == 'admin'

    def is_auditor(self):
        return self.role in ('admin', 'auditor')

    def is_auditee(self):
        return self.role == 'auditee'


IMPACT_AREA_CHOICES = [
    ('reputation',   'Reputation & Customer Confidence'),
    ('financial',    'Financial'),
    ('productivity', 'Productivity'),
    ('safety',       'Safety & Health'),
    ('legal',        'Fines & Legal Penalties'),
    ('custom',       'User-Defined / Other'),
]

CONTAINER_TYPE_CHOICES = [
    ('internal_technical', 'Internal Technical'),
    ('external_technical', 'External Technical'),
    ('physical',           'Physical'),
    ('people',             'People'),
]

CIA_CHOICES = [
    ('confidentiality', 'Confidentiality'),
    ('integrity',       'Integrity'),
    ('availability',    'Availability'),
]

PROBABILITY_CHOICES = [
    ('low',    'Low'),
    ('medium', 'Medium'),
    ('high',   'High'),
]

IMPACT_VALUE_CHOICES = [
    (1, 'Low'),
    (2, 'Moderate'),
    (3, 'High'),
]

MITIGATION_CHOICES = [
    ('mitigate', 'Mitigate'),
    ('transfer', 'Transfer'),
    ('accept',   'Accept'),
    ('avoid',    'Avoid'),
    ('defer',    'Defer'),
]


# ══════════════════════════════════════════════════════════════
# ASSESSMENT  (top-level container)
# ══════════════════════════════════════════════════════════════

class Assessment(models.Model):
    STATUS_CHOICES = [
        ('draft',       'Draft'),
        ('in_progress', 'In Progress'),
        ('completed',   'Completed'),
    ]
    owner            = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                           related_name='assessments',
                           help_text='Auditor responsible for this assessment.')
    assigned_auditee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                           related_name='assigned_assessments',
                           help_text='Auditee organization being assessed.')
    title          = models.CharField(max_length=255)
    organization   = models.CharField(max_length=255)
    scope          = models.TextField(help_text='Describe the scope and boundaries of this assessment.')
    assessor_name  = models.CharField(max_length=255)
    assessor_email = models.EmailField(blank=True)
    start_date     = models.DateField(default=timezone.now)
    end_date       = models.DateField(null=True, blank=True)
    status         = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    notes          = models.TextField(blank=True)
    created_at     = models.DateTimeField(default=timezone.now)
    updated_at     = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.title} — {self.organization}'

    def get_impact_priorities(self):
        """Return {area_key: priority_rank} dict for this assessment."""
        return {p.impact_area: p.priority_rank for p in self.impact_priorities.all()}

    def get_all_threats(self):
        return ThreatScenario.objects.filter(asset__assessment=self)

    def get_risk_summary(self):
        threats = self.get_all_threats()
        scores = [t.compute_risk_score() for t in threats]
        counts = {'high': 0, 'medium': 0, 'low': 0}
        for s in scores:
            counts[s['level']] += 1
        return counts

    def is_step1_complete(self):
        return self.impact_criteria.exists() and self.impact_priorities.exists()

    def is_step2_complete(self):
        return self.assets.exists()

    def is_step3_complete(self):
        return AssetContainer.objects.filter(asset__assessment=self).exists()

    def is_step4_complete(self):
        return ThreatScenario.objects.filter(asset__assessment=self, area_of_concern__isnull=False).exclude(area_of_concern='').exists()

    def is_step5_complete(self):
        return ThreatScenario.objects.filter(asset__assessment=self).exists()

    def is_step7_complete(self):
        return ThreatScenario.objects.filter(asset__assessment=self, impact_area__isnull=False).exists()

    def is_step8_complete(self):
        return ThreatScenario.objects.filter(asset__assessment=self, mitigation_strategy__isnull=False).exclude(mitigation_strategy='').exists()


# ══════════════════════════════════════════════════════════════
# WS-1 to WS-6  — IMPACT CRITERIA (one row per criterion per area)
# ══════════════════════════════════════════════════════════════

class ImpactCriteria(models.Model):
    """
    WS-1 through WS-6.
    For each impact area the user defines what Low / Moderate / High means
    for their organisation (e.g. 'Revenue loss < 15%' = Low for Financial).
    Each ImpactCriteria row is one *criterion name* (sub-area) with 3 text cells.
    """
    assessment    = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='impact_criteria')
    impact_area   = models.CharField(max_length=20, choices=IMPACT_AREA_CHOICES)
    area_label    = models.CharField(max_length=255,
                        help_text='Custom label if "User-Defined", e.g. "Operational Continuity"',
                        blank=True)
    criterion     = models.CharField(max_length=255,
                        help_text='Name of this sub-criterion, e.g. "Revenue Loss", "Customer Loss"')
    low_criteria  = models.TextField(help_text='Describe what constitutes a LOW impact for this criterion.')
    mod_criteria  = models.TextField(help_text='Describe what constitutes a MODERATE impact for this criterion.')
    high_criteria = models.TextField(help_text='Describe what constitutes a HIGH impact for this criterion.')
    created_at    = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['impact_area', 'criterion']

    def __str__(self):
        return f'[{self.get_impact_area_display()}] {self.criterion}'

    def get_area_display_name(self):
        if self.impact_area == 'custom' and self.area_label:
            return self.area_label
        return self.get_impact_area_display()


# ══════════════════════════════════════════════════════════════
# WS-7  — IMPACT AREA PRIORITIZATION
# ══════════════════════════════════════════════════════════════

class ImpactPriority(models.Model):
    """
    WS-7: Rank impact areas from most important (5) to least (1).
    The rank directly multiplies into the risk score in Step 7.
    """
    assessment   = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='impact_priorities')
    impact_area  = models.CharField(max_length=20, choices=IMPACT_AREA_CHOICES)
    area_label   = models.CharField(max_length=255, blank=True,
                       help_text='If custom area, enter its name here.')
    priority_rank = models.IntegerField(
                       help_text='Rank: 5 = most important, 1 = least important. Each rank must be unique.',
                       choices=[(i, str(i)) for i in range(1, 6)])

    class Meta:
        ordering = ['-priority_rank']
        unique_together = [('assessment', 'impact_area'), ('assessment', 'priority_rank')]

    def __str__(self):
        return f'{self.get_impact_area_display()} — Rank {self.priority_rank}'

    def get_area_display_name(self):
        if self.impact_area == 'custom' and self.area_label:
            return self.area_label
        return self.get_impact_area_display()


# ══════════════════════════════════════════════════════════════
# WS-8  — INFORMATION ASSET PROFILE
# ══════════════════════════════════════════════════════════════

class InformationAsset(models.Model):
    """
    WS-8: Information Asset Profile.
    Identifies the asset, its owner, security requirements, and most important requirement.
    """
    ASSET_OWNER_TYPE = [
        ('internal', 'Internal'),
        ('external', 'External'),
    ]

    assessment        = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='assets')
    name              = models.CharField(max_length=255, help_text='Name of the information asset.')
    description       = models.TextField(help_text='Brief description of what this asset is.')
    rationale         = models.TextField(
                            help_text='Why is this asset important? What would happen if it were lost or compromised?')
    owner             = models.CharField(max_length=255, help_text='Person or group responsible for this asset.')
    owner_type        = models.CharField(max_length=10, choices=ASSET_OWNER_TYPE, default='internal')

    # Security requirements — CIA Triad
    req_confidentiality = models.TextField(
                              help_text='Who should have access? What would disclosure cause?')
    req_integrity       = models.TextField(
                              help_text='What accuracy/completeness requirements exist? Impact of modification?')
    req_availability    = models.TextField(
                              help_text='How available must this asset be? Impact of downtime?')

    most_important_req  = models.CharField(max_length=20, choices=CIA_CHOICES,
                              help_text='Which single CIA property is MOST critical for this asset?')

    created_at = models.DateTimeField(default=timezone.now)
    notes      = models.TextField(blank=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_risk_score_display(self):
        threats = self.threats.all()
        if not threats:
            return None
        scores = [t.compute_risk_score() for t in threats]
        total = max(s['total'] for s in scores)
        return total


# ══════════════════════════════════════════════════════════════
# WS-9  — ASSET CONTAINER (Risk Environment Map)
# ══════════════════════════════════════════════════════════════

class AssetContainer(models.Model):
    """
    WS-9: Where is the asset stored, transported, or processed?
    Maps the information asset's risk environment.
    Three map types: Internal Technical, External Technical, Physical, People.
    """
    asset          = models.ForeignKey(InformationAsset, on_delete=models.CASCADE, related_name='containers')
    container_type = models.CharField(max_length=30, choices=CONTAINER_TYPE_CHOICES)
    name           = models.CharField(max_length=255, help_text='Name of this container (e.g. "Email Server", "HR Department")')
    description    = models.TextField(help_text='Describe this container and how the asset is stored/transported/processed here.')
    location       = models.CharField(max_length=255, blank=True,
                         help_text='Physical or network location of this container.')
    owner          = models.CharField(max_length=255, blank=True,
                         help_text='Who owns or manages this container?')
    is_critical    = models.BooleanField(default=False,
                         help_text='Is this a critical container for this asset?')
    notes          = models.TextField(blank=True)
    created_at     = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['container_type', 'name']

    def __str__(self):
        return f'{self.get_container_type_display()} — {self.name}'


# ══════════════════════════════════════════════════════════════
# WS-10  — INFORMATION ASSET RISK WORKSHEET (Threat Scenario)
# ══════════════════════════════════════════════════════════════

class ThreatScenario(models.Model):
    """
    WS-10: Information Asset Risk Worksheet.
    One row per threat scenario. Contains:
      - Area of Concern (Step 4)
      - 7-field threat description: Actor, Means, Motive, Outcome, Access Path, Probability, Consequences
      - Impact classification per impact area (Step 6)
      - Risk score computation (Step 7)
      - Mitigation plan (Step 8)
    """
    asset          = models.ForeignKey(InformationAsset, on_delete=models.CASCADE, related_name='threats')
    container      = models.ForeignKey(AssetContainer, on_delete=models.SET_NULL, null=True, blank=True,
                         related_name='threats',
                         help_text='Which container does this threat originate from or affect?')

    # ── Step 4: Area of Concern ───────────────────────────────
    area_of_concern = models.TextField(
                          help_text='Describe the area of concern that prompted this threat scenario.')

    # ── Step 5: Threat Scenario (7 properties) ────────────────
    scenario_name  = models.CharField(max_length=255, help_text='Brief name for this threat scenario.')
    actor          = models.TextField(
                         help_text='(1) Actor — Who would exploit this area of concern or threat? '
                                   'e.g. Hacker, Insider, Competitor, Natural disaster.')
    means          = models.TextField(
                         help_text='(2) Means — How would the actor do it? What tools or methods would they use?')
    motive         = models.TextField(
                         help_text="(3) Motive — What is the actor's reason for doing this?")
    outcome        = models.TextField(
                         help_text='(4) Outcome — What would be the resulting effect on the information asset? '
                                   '(Disclosure, Modification, Destruction, Interruption)')
    access_path    = models.TextField(
                         help_text='(5) Access Path — How would the actor gain access to the asset or its containers?')
    probability    = models.CharField(max_length=10, choices=PROBABILITY_CHOICES, default='medium',
                         help_text='(6) Probability — How likely is this threat scenario to occur?')
    consequences   = models.TextField(
                         help_text='(7) Consequences — What are the consequences to the organisation '
                                   'if this threat is realised? Consider the most important security requirement.')

    # ── Step 6 + 7: Impact classification ────────────────────
    impact_area    = models.CharField(max_length=20, choices=IMPACT_AREA_CHOICES, null=True, blank=True,
                         help_text='Which impact area is most affected by this threat?')
    impact_value   = models.IntegerField(choices=IMPACT_VALUE_CHOICES, null=True, blank=True,
                         help_text='Step 7 — Classify the impact: Low=1, Moderate=2, High=3.')
    impact_rationale = models.TextField(blank=True,
                           help_text='Briefly explain why you chose this impact level.')

    # ── Step 8: Mitigation ────────────────────────────────────
    mitigation_strategy  = models.CharField(max_length=10, choices=MITIGATION_CHOICES, null=True, blank=True)
    mitigation_plan      = models.TextField(blank=True,
                               help_text='Describe what will be done to address this risk.')
    mitigation_rationale = models.TextField(blank=True,
                               help_text='Why was this mitigation strategy chosen?')
    responsible_party    = models.CharField(max_length=255, blank=True)
    target_date          = models.DateField(null=True, blank=True)
    mitigation_status    = models.CharField(max_length=20, choices=[
                               ('planned',     'Planned'),
                               ('in_progress', 'In Progress'),
                               ('completed',   'Completed'),
                               ('deferred',    'Deferred'),
                           ], default='planned', blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    notes      = models.TextField(blank=True)

    class Meta:
        ordering = ['asset', 'scenario_name']

    def __str__(self):
        return f'{self.scenario_name} — {self.asset.name}'

    def compute_risk_score(self):
        """
        Official OCTAVE Allegro Step 7 formula:
          Risk Score = impact_value (1/2/3)  ×  impact_area_priority_rank (1-5)

        Returns a dict with: score, rank, level, impact_label
        """
        if not self.impact_value or not self.impact_area:
            return {'total': 0, 'rank': 0, 'level': 'unscored', 'impact_label': '—'}

        priorities = self.asset.assessment.get_impact_priorities()
        rank = priorities.get(self.impact_area, 1)
        total = self.impact_value * rank

        # Max possible = 3 × 5 = 15
        if total >= 10:
            level = 'high'
        elif total >= 5:
            level = 'medium'
        else:
            level = 'low'

        return {
            'total': total,
            'rank': rank,
            'level': level,
            'impact_label': dict(IMPACT_VALUE_CHOICES).get(self.impact_value, '—'),
        }

    def get_probability_color(self):
        return {'low': 'success', 'medium': 'warning', 'high': 'danger'}.get(self.probability, 'secondary')


# ── Auto-create profile on user creation ─────────────────────
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)

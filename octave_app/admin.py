from django.contrib import admin
from .models import (Assessment, ImpactCriteria, ImpactPriority,
                     InformationAsset, AssetContainer, ThreatScenario, UserProfile)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'organization', 'created_at']
    list_filter  = ['role']
    search_fields = ['user__username', 'organization']

from .models import Assessment, ImpactCriteria, ImpactPriority, InformationAsset, AssetContainer, ThreatScenario

class ImpactCriteriaInline(admin.TabularInline):
    model = ImpactCriteria; extra = 0

class ImpactPriorityInline(admin.TabularInline):
    model = ImpactPriority; extra = 0

@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ['title', 'organization', 'assessor_name', 'status', 'created_at']
    list_filter  = ['status']
    inlines      = [ImpactCriteriaInline, ImpactPriorityInline]

class AssetContainerInline(admin.TabularInline):
    model = AssetContainer; extra = 0

class ThreatInline(admin.TabularInline):
    model = ThreatScenario; extra = 0
    fields = ['scenario_name', 'probability', 'impact_area', 'impact_value', 'mitigation_strategy']

@admin.register(InformationAsset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ['name', 'assessment', 'owner', 'most_important_req']
    inlines = [AssetContainerInline, ThreatInline]

admin.site.register(ImpactCriteria)
admin.site.register(ImpactPriority)
admin.site.register(AssetContainer)
admin.site.register(ThreatScenario)

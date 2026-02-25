from django.urls import path
from . import views

urlpatterns = [
    # ── Auth / Module 1 ──────────────────────────────────────
    path('login/',                    views.login_view,   name='login'),
    path('register/',                 views.register_view,name='register'),
    path('logout/',                   views.logout_view,  name='logout'),
    path('profile/',                  views.profile_view, name='profile'),
    path('users/',                    views.user_list,    name='user_list'),
    path('users/<int:user_pk>/edit/', views.user_edit,    name='user_edit'),
    path('users/<int:user_pk>/delete/', views.user_delete, name='user_delete'),

    # Dashboard & Assessment
    path('',                                     views.dashboard,          name='dashboard'),
    path('assessments/',                          views.assessment_list,    name='assessment_list'),
    path('assessments/new/',                      views.assessment_create,  name='assessment_create'),
    path('assessments/<int:pk>/',                 views.assessment_detail,  name='assessment_detail'),
    path('assessments/<int:pk>/edit/',            views.assessment_update,  name='assessment_update'),
    path('assessments/<int:pk>/delete/',          views.assessment_delete,  name='assessment_delete'),
    path('assessments/<int:pk>/report/',          views.generate_report,    name='generate_report'),
    path('assessments/<int:pk>/assign-auditee/',  views.assign_auditee,     name='assign_auditee'),

    # Step 1 — WS-1 to WS-7
    path('assessments/<int:pk>/step1/',                      views.step1_criteria,       name='step1_criteria'),
    path('assessments/<int:pk>/step1/add/',                  views.step1_criteria_add,   name='step1_criteria_add'),
    path('assessments/<int:pk>/step1/<int:crit_pk>/edit/',   views.step1_criteria_edit,  name='step1_criteria_edit'),
    path('assessments/<int:pk>/step1/<int:crit_pk>/delete/', views.step1_criteria_delete,name='step1_criteria_delete'),
    path('assessments/<int:pk>/step1/prioritize/',           views.step1_prioritize,     name='step1_prioritize'),

    # Step 2 — WS-8
    path('assessments/<int:pk>/assets/new/',  views.step2_asset_add,    name='step2_asset_add'),
    path('assets/<int:asset_pk>/edit/',       views.step2_asset_edit,   name='step2_asset_edit'),
    path('assets/<int:asset_pk>/delete/',     views.step2_asset_delete, name='step2_asset_delete'),

    # Step 3 — WS-9
    path('assets/<int:asset_pk>/containers/',         views.step3_containers,      name='step3_containers'),
    path('assets/<int:asset_pk>/containers/add/',     views.step3_container_add,   name='step3_container_add'),
    path('containers/<int:container_pk>/edit/',       views.step3_container_edit,  name='step3_container_edit'),
    path('containers/<int:container_pk>/delete/',     views.step3_container_delete,name='step3_container_delete'),

    # Steps 4-8 — WS-10
    path('assets/<int:asset_pk>/threats/add/',  views.step4_threat_add,    name='step4_threat_add'),
    path('threats/<int:threat_pk>/edit/',       views.step4_threat_edit,   name='step4_threat_edit'),
    path('threats/<int:threat_pk>/delete/',     views.step4_threat_delete, name='step4_threat_delete'),
]


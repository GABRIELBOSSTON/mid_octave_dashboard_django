OCTAVE_STEPS = [
    ('1', 'Establish Risk Measurement Criteria',  'WS-1 to WS-7'),
    ('2', 'Develop Information Asset Profile',     'WS-8'),
    ('3', 'Identify Asset Containers',             'WS-9'),
    ('4', 'Identify Areas of Concern',             'WS-10 Part A'),
    ('5', 'Identify Threat Scenarios',             'WS-10 Part B'),
    ('6', 'Identify Risks',                        'WS-10 Part C'),
    ('7', 'Analyze Risks',                         'WS-10 Part D'),
    ('8', 'Select Mitigation Approach',            'WS-10 Part E'),
]

def sidebar_ctx(request):
    return {'octave_steps': OCTAVE_STEPS}

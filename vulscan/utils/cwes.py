# fmt: off
# clean
clean_train_cwes = {
    "c": [
        "CWE-22", "CWE-23", "CWE-121", "CWE-125", "CWE-134", "CWE-176", "CWE-190", "CWE-191",
        "CWE-319", "CWE-327", "CWE-338", "CWE-367", "CWE-369", "CWE-400", "CWE-416", "CWE-457",
        "CWE-476", "CWE-526", "CWE-758", "CWE-761", "CWE-787", "CWE-843"
    ],
    "python": [
        "CWE-74", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95", "CWE-120", "CWE-179", "CWE-200",
        "CWE-295", "CWE-327", "CWE-352", "CWE-367", "CWE-400", "CWE-502", "CWE-611", "CWE-862",
        "CWE-863", "CWE-915", "CWE-918"
    ]
}
hard_train_cwes = {
    "c": ['CWE-119', 'CWE-125', 'CWE-190', 'CWE-20', 'CWE-200', 'CWE-22', 'CWE-269',
          'CWE-287', 'CWE-307', 'CWE-327', 'CWE-352', 'CWE-400', 'CWE-415', 'CWE-416',
          'CWE-476', 'CWE-502', 'CWE-77', 'CWE-78', 'CWE-787', 'CWE-79', 'CWE-798',
          'CWE-862', 'CWE-863', 'CWE-89', 'CWE-918', 'CWE-94']
}
long_context_train_cwes = {
    "c": [
        "CWE-125", "CWE-416", "CWE-787",
        ]
}
clean_test_cwes = {
    "c": [
        "CWE-15", "CWE-22", "CWE-23", "CWE-78", "CWE-90", "CWE-121", "CWE-122", "CWE-123",
        "CWE-124", "CWE-125", "CWE-134", "CWE-176", "CWE-190", "CWE-191", "CWE-242", "CWE-252",
        "CWE-319", "CWE-327", "CWE-338", "CWE-367", "CWE-369", "CWE-400", "CWE-401", "CWE-415",
        "CWE-416", "CWE-426", "CWE-457", "CWE-476", "CWE-506", "CWE-526", "CWE-590", "CWE-667",
        "CWE-681", "CWE-758", "CWE-761", "CWE-775", "CWE-787", "CWE-843"
    ],
    "python": [
        "CWE-1333", "CWE-200", "CWE-22", "CWE-281", "CWE-367", "CWE-611",
        "CWE-77", "CWE-79", "CWE-295", "CWE-862", "CWE-352", "CWE-915",
        "CWE-94", "CWE-327", "CWE-95", "CWE-400", "CWE-338",
        "CWE-502", "CWE-179", "CWE-918", "CWE-120", "CWE-89",
        "CWE-863", "CWE-601", "CWE-74", "CWE-78",
    ],
}

train_c_cwes = set(clean_train_cwes["c"])
train_python_cwes = set(clean_train_cwes["python"])
train_c_cwes.update(set(hard_train_cwes["c"]))
train_c_cwes.update(set(long_context_train_cwes["c"]))
clean_ood_cwes = {
    "c": list(set(clean_test_cwes["c"]).difference(train_c_cwes)),
    "python": list(set(clean_test_cwes["python"]).difference(train_python_cwes)),
    "java": [],
}

# clean_ood_cwes = {
#     "c": [
#         'CWE-122', 'CWE-123', 'CWE-124', 'CWE-15', 'CWE-242', 'CWE-252', 'CWE-376',
#         'CWE-401', 'CWE-415', 'CWE-426', 'CWE-506', 'CWE-590', 'CWE-667', 'CWE-681',
#         'CWE-775', 'CWE-90', "CWE-78"
#     ],
#     "python": [
#         "CWE-1333", "CWE-22", "CWE-281",
#         "CWE-338", "CWE-77", "CWE-601",
#     ],
# }
hard_test_cwes = {
    "c": [
        "CWE-20", "CWE-119", "CWE-120", "CWE-125", "CWE-190", "CWE-200", "CWE-362",
        "CWE-401", "CWE-416", "CWE-476", "CWE-617", "CWE-703", "CWE-787"
    ],
}
hard_ood_cwes = {
    "c": list(set(hard_test_cwes["c"]).difference(train_c_cwes))
}

primevul_test_cwes = {
    "c": ['CWE-119', 'CWE-120', 'CWE-122', 'CWE-125', 'CWE-134', 'CWE-190', 'CWE-191',
          'CWE-193', 'CWE-20', 'CWE-200', 'CWE-212', 'CWE-22', 'CWE-252', 'CWE-269',
          'CWE-276', 'CWE-284', 'CWE-287', 'CWE-288', 'CWE-295', 'CWE-327', 'CWE-345',
          'CWE-354', 'CWE-362', 'CWE-369', 'CWE-400', 'CWE-401', 'CWE-415', 'CWE-416',
          'CWE-434', 'CWE-444', 'CWE-476', 'CWE-522', 'CWE-552', 'CWE-59', 'CWE-617',
          'CWE-665', 'CWE-668', 'CWE-672', 'CWE-703', 'CWE-704', 'CWE-732', 'CWE-754',
          'CWE-770', 'CWE-772', 'CWE-787', 'CWE-79', 'CWE-824', 'CWE-834', 'CWE-835',
          'CWE-843', 'CWE-862', 'CWE-863', 'CWE-908', 'CWE-909', 'CWE-924', 'CWE-94']
}
primevul_ood_cwes = {
    "c": list(set(primevul_test_cwes["c"]).difference(train_c_cwes))
}
tmp_cwes = {
    "python": [
        "CWE-200", "CWE-22", "CWE-281",
        "CWE-295", "CWE-862", "CWE-400",
        "CWE-918", "CWE-863", "CWE-601",
    ],
}

test_cwes={
    "c": ["CWE-20", "CWE-119", "CWE-120", "CWE-125", "CWE-190", "CWE-200", "CWE-362", "CWE-401", "CWE-416", "CWE-476",
          "CWE-617", "CWE-617", "CWE-703", "CWE-787"]
}
function_level_train_cwes = {
    "c": [
    "CWE-20","CWE-22","CWE-23","CWE-77","CWE-78","CWE-79","CWE-89","CWE-94","CWE-119","CWE-120","CWE-121","CWE-125","CWE-134","CWE-176","CWE-190","CWE-191","CWE-200","CWE-269","CWE-287","CWE-307","CWE-319","CWE-327","CWE-338","CWE-352",
    "CWE-362","CWE-367","CWE-369","CWE-400","CWE-401","CWE-415","CWE-416","CWE-457","CWE-476","CWE-502","CWE-526",
    "CWE-617","CWE-703","CWE-758","CWE-761","CWE-787","CWE-798","CWE-843","CWE-862","CWE-863","CWE-918"
],
    "python":["CWE-74", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95", "CWE-120",
              "CWE-179", "CWE-200", "CWE-295", "CWE-327", "CWE-352", "CWE-367", "CWE-400",
              "CWE-502", "CWE-611", "CWE-862", "CWE-863", "CWE-915", "CWE-918"]
}
function_level_test_cwes = {
    "c": ["CWE-15", "CWE-20", "CWE-22", "CWE-23", "CWE-78", "CWE-90", "CWE-119", "CWE-120", "CWE-121", "CWE-122",
          "CWE-123", "CWE-124", "CWE-125", "CWE-134", "CWE-176", "CWE-190", "CWE-191", "CWE-200", "CWE-242", "CWE-252",
          "CWE-319", "CWE-327", "CWE-338", "CWE-362", "CWE-367", "CWE-369", "CWE-400", "CWE-401", "CWE-415", "CWE-416",
          "CWE-426", "CWE-457", "CWE-476", "CWE-506", "CWE-526", "CWE-590", "CWE-617", "CWE-667", "CWE-681", "CWE-703",
          "CWE-758", "CWE-761", "CWE-775", "CWE-787", "CWE-843"],
    "python": ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95", "CWE-120", "CWE-179", "CWE-200", "CWE-281", "CWE-295",
               "CWE-327", "CWE-338", "CWE-347", "CWE-400", "CWE-502", "CWE-601", "CWE-611", "CWE-732", "CWE-770",
               "CWE-862", "CWE-863", "CWE-915", "CWE-918", "CWE-1333"],
    "java": ["CWE-15", "CWE-23", "CWE-78", "CWE-89", "CWE-90", "CWE-113", "CWE-129", "CWE-134", "CWE-190", "CWE-191",
             "CWE-193", "CWE-252", "CWE-319", "CWE-327", "CWE-338", "CWE-369", "CWE-400", "CWE-476", "CWE-526", "CWE-601",
             "CWE-617", "CWE-667", "CWE-681", "CWE-772", "CWE-775", "CWE-835"],
}
function_level_ood_cwes = {
    "c": list(set(function_level_test_cwes["c"]).difference(function_level_train_cwes["c"])),
    "python": list(set(function_level_test_cwes["python"]).difference(function_level_train_cwes["python"])),
}
repo_level_test_cwes = {
    "java": ["CWE-20", "CWE-22", "CWE-74", "CWE-79", "CWE-89", "CWE-200", "CWE-284", "CWE-287", "CWE-295", "CWE-327",
             "CWE-345", "CWE-352", "CWE-400", "CWE-434", "CWE-444", "CWE-502", "CWE-522", "CWE-611", "CWE-668", "CWE-770",
             "CWE-787", "CWE-835", "CWE-862", "CWE-863", "CWE-918", "CWE-1021"]
}
java_ood_cwes = {
    "java": list(set(repo_level_test_cwes["java"]).union(function_level_test_cwes["java"]))
}
# fmt: on

remove_idx = ["121", "408"]

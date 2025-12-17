# Generate data


# Example of the output format:
# {
#     "language": "",
#     "fix_commit": "",
#     "vuln_commit": "",
#     "local_id": "",
#     "sanitizer": "",
#     "crash_type": "",
#     "patch": "",
#     "function_before_patch": [
#         {
#             "function_name": "",
#             "function_body": "", # with the function signature
#             "file_path": ""
#         },
#       ]
#     "function_after_patch": [
#         {
#             "function_name": "",
#             "function_body": "", # with the function signature
#             "file_path": ""
#         },
#       ]
#     "functions_in_stack_trace": [
#         {
#             "function_name": "",
#             "function_body": "", # with the function signature
#             "file_path": ""
#         },
#         {
#             "function_name": "",
#             "function_body": "", # with the function signature
#             "file_path": ""
#         }
#     ],
#     "sanitizer_output": "",
#     "project_name": "",
#     "if_vuln_crash": "",
# }

import argparse
import os
import json
import re
import sys
import subprocess
import json
import re
import sys
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed

########################################################
# utils from another project
########################################################

from collections import defaultdict
from tree_sitter_languages import get_parser


# ---------- C ----------
def find_c_function(node, cur_class=None):
    """
    Return (qualified_name, start_line, end_line) for a C function_definition.
    """
    if node.type != "function_definition" or b"enum" in node.text:
        return None

    declarator = node.child_by_field_name("declarator")
    if not declarator:
        return None

    ident = declarator.child_by_field_name("declarator")
    if not ident:
        return None

    name_node = next((c for c in ident.children if c.type == "identifier"), ident)
    fname = name_node.text.decode()

    if cur_class:
        fname = f"{cur_class}::{fname}"

    return fname, node.start_point[0] + 1, node.end_point[0] + 1


# ---------- C++ ----------
def find_cpp_function(node, cur_class=None):
    """
    Handle ordinary functions, constructors, destructors and operators.
    """
    if node.type not in (
        "function_definition",
        "constructor_definition",
        "destructor_definition",
    ):
        return None

    declarator = node.child_by_field_name("declarator")
    if not declarator:
        return None
    inner = declarator.child_by_field_name("declarator")
    if not inner:
        inner = next((c for c in declarator.children if c.type.endswith("declarator")), None)
        if not inner:
            return None

    # Choose the first child that looks like an identifier / destructor / operator token
    name_node = next(
        (
            c
            for c in inner.children
            if c.type in ("identifier", "destructor_name", "operator")
        ),
        inner,
    )

    fname = name_node.text.decode()
    if cur_class and not fname.startswith(f"{cur_class}::"):
        fname = f"{cur_class}::{fname}"

    return fname, node.start_point[0] + 1, node.end_point[0] + 1


# ---------- Java ----------
def find_java_function(node, cur_class=None):
    """
    Handle method_declaration and constructor_declaration.
    """
    if node.type not in ("method_declaration", "constructor_declaration"):
        return None

    name_node = node.child_by_field_name("name")
    if not name_node:
        return None

    fname = name_node.text.decode()
    if cur_class:
        fname = f"{cur_class}.{fname}"

    return fname, node.start_point[0] + 1, node.end_point[0] + 1


# ---------- Collector ----------
def get_function_info(code: str, lang: str = "cpp"):
    """
    Parse source code and return a dictionary:

        { qualified_name : [(start_line, end_line), ...] }

    * For overloaded functions or multiple constructors,
      all occurrences are preserved in the value list.
    """
    if not lang:
        return None
    
    parser = get_parser(lang)
    tree = parser.parse(code.encode())
    root = tree.root_node

    dispatch = {
        "c": find_c_function,
        "cpp": find_cpp_function,
        "java": find_java_function,
    }
    find_func = dispatch[lang]

    functions = defaultdict(list)

    stack = [(root, None)]  # (node, current_class)
    while stack:
        node, cur_class = stack.pop()

        # Update current class name when entering a class / struct / interface
        if node.type in (
            "class_specifier",
            "struct_specifier",
            "class_declaration",
            "interface_declaration",
        ):
            name_node = node.child_by_field_name("name")
            if name_node:
                cur_class = name_node.text.decode()

        # Push children to stack
        for child in reversed(node.children):
            stack.append((child, cur_class))

        # Collect functions / methods / constructors / destructors
        if node.type in {
            "function_definition",
            "constructor_definition",
            "destructor_definition",
            "method_declaration",
            "constructor_declaration",
        }:
            res = find_func(node, cur_class)
            if res:
                fname, l0, l1 = res
                fname = fname.replace("\n", "")
                functions[fname].append((l0, l1))

    return functions

########################################################
# utils from another project
########################################################

import requests
import os
from urllib.parse import urlparse
import json
import re
def get_commit_info(commit_url, github_token=None):
    if not commit_url.startswith("https://github.com"):
        print("Warning: Currently only support GitHub repositories.")
        return None
    
    headers = {"Accept": "application/vnd.github+json"}
    
    github_token = os.environ.get("GITHUB_TOKEN")
    if github_token is not None:
        headers["Authorization"] = f"Bearer {github_token}"
    else:
        print("Warning: GitHub token not found. Rate limits may apply.")


    parsed_url = urlparse(commit_url)
    parts = parsed_url.path.strip('/').split('/')
    repository = "/".join(parts[:2])
    commit_sha = parts[-1]

    # print("Repository:", repository)
    # print("Commit SHA:", commit_sha)
    # Get commit details from GitHub API
    api_url = f'https://api.github.com/repos/{repository}/commits/{commit_sha}'
    commit_info = requests.get(api_url, headers=headers).json()
    
    # with open("temp.json", "w") as f:
    #     json.dump(commit_info, f, indent=4)
    #     print("Commit info saved to temp.json")
    return commit_info

def get_previous_commit_sha(commit_info):

    # Extract parent SHA (previous commit)
    parents = commit_info.get('parents', [])
    if parents:
        prev_commit_url = parents[0]['url']
        return prev_commit_url
    else:
        print("This commit has no parent (initial commit).")
        return None

    
def extract_function_name(signature):
    """
    Given a function signature string, extract the function name.
    For example:
      'MagickExport int EOFBlob(const Image *image)'
    will return:
      'EOFBlob'
    """
    # Split by '(' and take the part before it.
    if '(' in signature:
        before_paren = signature.split('(')[0].strip()
        # The function name is assumed to be the last token in the string.
        tokens = before_paren.split()
        if tokens:
            return tokens[-1]
    return signature.strip()

def get_file_and_func_from_commit_info(commit_info_files):
    """
    return: A list of strings, each formatted as "relative_path__xx__function".
    """    
    file_changes = {}
    hunk_header_regex = re.compile(r"^@@.*@@\s*(.*)$")
    for commit_file_change in commit_info_files:
        file_name = commit_file_change['filename']
        patch = commit_file_change['patch']    
        function_changed_in_file = set()
        for line in patch.splitlines():
            match = hunk_header_regex.match(line)
            if match:
                # Extract the context (which contains the function signature)
                context = match.group(1).strip()
                if context:
                    func_name = extract_function_name(context)
                    # result = f"{file_name}__xx__{func_name}"
                    # result = result.replace('/', '___') # replace / with ___
                    function_changed_in_file.add(func_name)   
        
        file_changes[file_name] = list(function_changed_in_file )
                    
    return file_changes                    

def strip_template_params(s):
    result = []
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c == '<':
            depth += 1
            i += 1
        elif c == '>':
            if depth > 0:
                depth -= 1
            else:
                result.append(c)  # Lone >, likely operator-> or malformed
            i += 1
        elif depth == 0:
            # Detect and preserve operator-> (advance by 2)
            if s.startswith("->", i):
                result.append("->")
                i += 2
            else:
                result.append(c)
                i += 1
        else:
            # Inside template param — skip
            i += 1
    return ''.join(result)


def find_function_from_major_back_trace(log_text):
    """ 
    This function extracts the function name and file path from the log text.
    returns a list of tuples containing the function name and absolute file path.
    
    Assuming that functions will be in the format similar to
        '# #0 0x689610 in TracePath /src/imagemagick/MagickCore/draw.c:6515:36'
    
    
    """

    lines = log_text.splitlines()
    function_lines = [] 
    collecting = False

    for line in lines:
        if re.match(r"^\s*#\d+", line):
            if not collecting:
                collecting = True
            function_lines.append(line)
        elif collecting:
            # End collection after the first block of consecutive stack lines
            break

    callstack_regex = re.compile(
        r"^\s*#\d+\s+\S+\s+in\s+(.+)\s+(?=/)(/[^:]+):(\d+):\d+"
    )

    results = []
    for entry in function_lines:
        m = callstack_regex.search(entry)
        if m:
            raw_func = m.group(1).strip()
            raw_func = strip_template_params(raw_func)
            func_match = re.match(r'^(.+?)\s*\(', raw_func)
            if func_match:
                func_name = func_match.group(1).split('::')[-1].strip()
            else:
                func_name = raw_func.split('::')[-1].strip()
            file_path = m.group(2).strip()
            line_number = int(m.group(3).strip())
            results.append((func_name, file_path, line_number))
    
    full_stack_trace = "\n".join(function_lines)
    return {
            "stack_trace": full_stack_trace,
            "function_and_file_path": results
            }

def get_function_stack_trace_dedup_token(log_text):
    '''
    This function extracts the dedup token and the function stack trace from the log text.
    '''
    dedup_results = {}
    dedup_regex = re.compile(r"^DEDUP_TOKEN:\s*(.+)$", re.MULTILINE)
    # Reuse our call stack regex from above.
    # We'll find each dedup token and then examine the text from its end until the next dedup token.
    dedup_matches = list(dedup_regex.finditer(log_text))
    
    counter = 0
    for idx, dedup in enumerate(dedup_matches):
        dedup_text = dedup.group(1).strip()
        # print(dedup.end())
        # Determine the block of text following this dedup token.
        start_index = dedup.end()
        if idx + 1 < len(dedup_matches):
            end_index = dedup_matches[idx + 1].start()
        else:
            end_index = len(log_text)
        block_text = log_text[start_index:end_index]
        # print(block_text)
        
        result = find_function_from_major_back_trace(block_text)

        result['dedup_text'] = dedup_text
        
        dedup_results[f"DEDUP_TOKEN_{counter}"] = result
        counter += 1
        
    return dedup_results
 
def get_lang_from_filename(filename):
    """Get the language from the filename."""
    filename = str(filename)
    if filename.endswith(".c"):
        return "c"
    elif filename.endswith(".cpp") or filename.endswith(".cc") or filename.endswith(".cxx") or filename.endswith(".hpp") or filename.endswith(".hxx") or filename.endswith(".h") or filename.endswith(".h++") or filename.endswith(".hh"): 
        return "cpp"
    elif filename.endswith(".java"):
        return "java"
    else:
        return None


def get_line_from_function(function, start_line, end_line, target_line):
    """
    Given a function object, start line, end line, and target line, return the line content in the function.
    """
    if start_line <= target_line <= end_line:
        return function.splitlines()[target_line - start_line]
    else:
        return ""

########################################################
# utils from another project
########################################################

import docker
import time
import io
import tarfile
import os
import shutil
import subprocess
from collections import deque
from docker.errors import NotFound, APIError
import re
import tempfile
client = docker.from_env(timeout=300)

def function_file_path_formatter(file_path, function_name):
    """
    Formats the file path and function name into a single string.
    """
    return f"{file_path}__xx__{function_name}"

def copy_directory_from_container(container_id, src_path, dst_path):
    container = client.containers.get(container_id)
    exec_result = container.exec_run(f"ls -la {src_path}")
    if exec_result.exit_code != 0:
        raise ValueError(f"Path {src_path} does not exist in the container.")

    if os.path.exists(dst_path):
        shutil.rmtree(dst_path)
    os.makedirs(dst_path, exist_ok=True)

    stream, stats = container.get_archive(src_path)
    temp_tar = os.path.join(dst_path, "temp_archive.tar")

    with open(temp_tar, "wb") as f:
        for chunk in stream:
            f.write(chunk)

    with tarfile.open(temp_tar) as tar:
        tar.extractall(path=dst_path, numeric_owner=True)

    os.remove(temp_tar)

def copy_file_from_container(container_id, src_path, dst_path):
    container = client.containers.get(container_id)

    # Check if the file exists inside the container
    exec_result = container.exec_run(f"test -f {src_path}")
    if exec_result.exit_code != 0:
        raise FileNotFoundError(f"File {src_path} does not exist in the container.")

    # Retrieve the file as a tar stream
    stream, _ = container.get_archive(src_path)
    temp_tar = dst_path + ".tar"

    # Write the tar stream to a temporary file
    with open(temp_tar, "wb") as f:
        for chunk in stream:
            f.write(chunk)

    # Extract the file content and write it directly to dst_path
    with tarfile.open(temp_tar) as tar:
        members = tar.getmembers()
        file_member = members[0]
        fileobj = tar.extractfile(file_member)
        if fileobj is None:
            raise RuntimeError("Failed to extract file from the tar archive.")

        with open(dst_path, "wb") as out_file:
            out_file.write(fileobj.read())

    os.remove(temp_tar)


def copy_file_to_container(container_id, local_path, container_path):
    """
    Copy a single file to the container.
    container_path should be the full path to the target file in the container.
    """
    container = client.containers.get(container_id)

    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tar:
        tar.add(local_path, arcname=os.path.basename(container_path))
    data.seek(0)

    container_dir = os.path.dirname(container_path)
    container.exec_run(f"mkdir -p {container_dir}")
    container.put_archive(container_dir, data.getvalue())


def copy_directory_to_container(container_id, src_path, dst_path):
    """
    Copies a directory from the host (src_path) into the container (dst_path).
    If dst_path does not exist, it is created. Contents are overwritten.
    """
    container = client.containers.get(container_id)

    mkdir_cmd = f"mkdir -p {dst_path}"
    exit_code, output = container.exec_run(mkdir_cmd)
    if exit_code != 0:
        raise RuntimeError(f"Failed to create directory {dst_path} in container: {output.decode()}")

    mem_tar = io.BytesIO()
    with tarfile.open(fileobj=mem_tar, mode='w') as tar:
        tar.add(src_path, arcname="") 
    mem_tar.seek(0)

    container.put_archive(dst_path, mem_tar.getvalue())


def get_container(image_id, version="vul"):
    """Create and start a new container from the specified image."""
    image_name = f"n132/arvo:{image_id}-{version}"
    container = client.containers.run(image_name, command="bash", stdin_open=True, tty=True, detach=True)
    print(f"Container {container.id} started from image {image_name}")
    return container.id

def get_container_with_codeql(image_id, version="vul", codeql_path=None):
    """Create and start a new container from the specified image with CodeQL."""
    if not codeql_path:
        raise ValueError("CodeQL path is required to create the container.")
    image_name = f"n132/arvo:{image_id}-{version}"
    if codeql_path:
        container = client.containers.run(image_name, command="bash", stdin_open=True, tty=True, detach=True, volumes={codeql_path: {'bind': '/surfi/codeql', 'mode': 'rw'}})
    print(f"Container {container.id} with codeql started from image {image_name}")
    return container.id

def run_poc(container_id):
    """Run `arvo` inside the container and capture output."""
    container = client.containers.get(container_id)
    exec_result = container.exec_run("arvo", stdout=True, stderr=True)
    output = exec_result.output.decode("utf-8-sig", errors="ignore")
    return output

def checkout(container_id, commit, dir=""):
    """Checkout to the specified commit inside the container.
    If `dir` is provided, run the command inside that directory.
    """
    container = client.containers.get(container_id)
    
    if dir:
        checkout_command = f"bash -c 'cd {dir} && git checkout {commit}'"
    else:
        checkout_command = f"git checkout {commit}"
    
    result = container.exec_run(checkout_command)
    if result.exit_code != 0:
        raise RuntimeError(f"Checkout Command failed: {result.output.decode()}")
    print(f"Checked out commit {commit} in container {container_id}")
    return result

def reset(container_id, base_dir="/src"):
    """Perform git reset inside the container at the specified base_dir."""
    container = client.containers.get(container_id)
    reset_command = f"bash -c 'cd {base_dir} && git reset --hard'"
    result = container.exec_run(reset_command)
    if result.exit_code != 0:
        raise RuntimeError(f"Reset Command failed: {result.output.decode()}")
    print(f"Reset completed in container {container_id} at {base_dir}, output: {result.output.decode()}")
    return result

def reset_and_clean(container_id, base_dir="/src"):
    """Perform git reset and clean inside the container at the specified base_dir."""
    container = client.containers.get(container_id)
    reset_command = f"bash -c 'cd {base_dir} && git reset --hard && git clean -f -d -x'"
    result = container.exec_run(reset_command)
    if result.exit_code != 0:
        raise RuntimeError(f"Reset and Clean Command failed: {result.output.decode()}")
    print(f"Reset completed in container {container_id} at {base_dir}, output: {result.output.decode()}")
    return result

def compile_target(container_id):
    """Run 'arvo compile' inside the container's workdir."""
    container = client.containers.get(container_id)
    workdir = get_work_dir(container_id)
    compile_command = f"bash -c 'cd {workdir} && arvo compile'"
    exec_result = container.exec_run(compile_command, stdout=True, stderr=True)
    output = exec_result.output.decode()
    return output

def delete_container(container_id, max_wait=10):
    try:
        container = client.containers.get(container_id)
        container.remove(force=True, v=True)
    except NotFound:
        print(f"[info] container {container_id} already gone")
        return
    except APIError as e:
        print(f"[warn] docker API error on {container_id}: {e.explanation}")
        return
    for _ in range(max_wait):
        try:
            client.containers.get(container_id)
            time.sleep(1)
        except NotFound:
            print(f"Container {container_id} removed")
            return
    print(f"[warn] container {container_id} still listed after {max_wait}s")


def extract_file_from_container(container, filepath):
    """
    Extracts the content of the specified file from the container.
    Returns the file content as a decoded string.
    """
    stream, _ = container.get_archive(filepath)
    file_data = b""
    for chunk in stream:
        file_data += chunk
    tar_stream = io.BytesIO(file_data)
    with tarfile.open(fileobj=tar_stream) as tar:
        member = tar.getmembers()[0]
        f = tar.extractfile(member)
        content = f.read().decode()
    return content

def extract_file_from_container_bytes(container, filepath):
    """
    Extracts the content of the specified file from the container.
    Returns the file content as bytes.
    """
    stream, _ = container.get_archive(filepath)
    file_data = b""
    for chunk in stream:
        file_data += chunk
    tar_stream = io.BytesIO(file_data)
    with tarfile.open(fileobj=tar_stream) as tar:
        member = tar.getmembers()[0]
        f = tar.extractfile(member)
        content = f.read()
    return content

def create_tar_bytes(file_content, arcname):
    """
    Packs the given file content into a tar archive.
    
    :param file_content: The file content as a string.
    :param arcname: The name of the file inside the archive.
    :return: The tar archive as a byte string.
    """
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode='w') as tar:
        file_bytes = file_content.encode()
        tarinfo = tarfile.TarInfo(name=arcname)
        tarinfo.size = len(file_bytes)
        tar.addfile(tarinfo, io.BytesIO(file_bytes))
    tar_stream.seek(0)
    return tar_stream.read()

def check_crash(output):
    """
    Check if the poc still crashes the program.
    """
    return "sanitizer" in output.lower()

def get_function_content(container_id, key, lang="c", line_in_func = -1):
    """
    Retrieves the content of a specific function from a file inside the container.
    
    Input:
      - container_id: The ID of the Docker container.
      - key: A string in the format 'filepath__xx__functionname'.
      - lang: The programming language of the file. Default is 'c'.
    
    Returns:
      The content of the function as a string, or None if the function is not found.
    """
    container = client.containers.get(container_id)
    
    parts = key.split("__xx__")
    if len(parts) != 2:
        print(f"Key {key} is not in the correct format. Expected format: 'filepath__xx__functionname'")
        return "", -1, -1
    filepath, function_name = parts
    
    # Extract the file content from the container
    file_content = extract_file_from_container(container, filepath)
    # Use Tree-sitter to obtain function information from the file
    functions = get_function_info(file_content, lang)
    if not functions:
        return "", -1, -1
    if function_name not in functions:
        print(f"Initial try, Function {function_name} not found in file {filepath}")
        print("Trying to do partial matching, the result may be inaccurate")
        func_name = function_name.split("::")[-1]
        if func_name in functions:
            function_name = func_name
        else:
            return "", -1, -1
            # print("Trying to do partial matching with looser rules")
            # potential_funcs = [func for func in functions if func_name in func or func in func_name]
            # # get the distance between the function name and the potential function name
            # if potential_funcs:
            #     potential_funcs.sort(key=lambda f: abs(len(f) - len(func_name)))
            #     function_name = potential_funcs[0]
            # else:
            #     print("Trying to do partial matching with even looser rules....")
            #     func_name_clean = func_name.replace(" ", "")
            #     potential_funcs = [
            #         func for func in functions
            #         if func_name_clean in func.replace(" ", "") or func.replace(" ", "") in func_name_clean
            #     ]
            #     # get the distance between the function name and the potential function name
            #     if potential_funcs:
            #         potential_funcs.sort(key=lambda f: abs(len(f) - len(func_name)))
            #         function_name = potential_funcs[0]
            #     else:
            #         print(f"Function {function_name} finally not found in file {filepath}")
            #         return "", -1, -1
            
    # Get start and end line numbers (1-indexed), if line_in_func is not -1, we find the function that contains the line, otherwise we find the last function that matches the name
    # line_in_func helps to decide which function to extract when there are multiple functions with the same name
    if line_in_func != -1:
        for scope in functions[function_name]:
            start_line, end_line = scope
            if start_line <= line_in_func <= end_line:
                break
    else:
        start_line, end_line = functions[function_name][-1]
    
    # Split the file content into lines and extract the function content
    file_lines = file_content.splitlines()
    function_lines = file_lines[start_line - 1:end_line]  # convert 1-indexed to 0-indexed
    function_content = "\n".join(function_lines)
    
    return function_content, start_line, end_line

def get_file_content(container_id, filepath):
    """
    Retrieves the content of a file inside the container.
    
    Input:
      - container_id: The ID of the Docker container.
      - filepath: The path to the file inside the container.
    
    Returns:
      The content of the file as a string, or None if the file is not found.
    """
    container = client.containers.get(container_id)
    
    # Extract the file content from the container
    file_content = extract_file_from_container(container, filepath)
    
    return file_content

def run_command_in_container(container_id, command):
    """
    Run a command inside the container.
    """
    container = client.containers.get(container_id)
    full_command = f"/bin/bash -c \"{command}\""
    exec_result = container.exec_run(full_command, stdout=True, stderr=True)
    output = exec_result.output.decode()
    exit_code = exec_result.exit_code
    
    return output, exit_code

def get_work_dir(container_id):
    """
    Get the working directory of the container.
    """
    container = client.containers.get(container_id)
    work_dir, exit_code = run_command_in_container(container_id, "pwd").strip()
    return work_dir

def wrap_in_cd(command, basedir):
    if basedir:
        return f"bash -c 'cd {basedir} && {command}'"
    return command

def is_git_repo(path):
    return os.path.isdir(os.path.join(path, '.git'))

def commit_exists(repo_path, commit_hash):
    try:
        subprocess.run(
            ['git', 'cat-file', '-e', commit_hash],
            cwd=repo_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

def find_repos_with_commit(start_dir, target_commit):
    matched_repos = []
    queue = deque([start_dir])

    while queue:
        current = queue.popleft()
        try:
            entries = [os.path.join(current, entry) for entry in os.listdir(current)]
        except PermissionError:
            continue

        if is_git_repo(current):
            if commit_exists(current, target_commit):
                matched_repos.append(current)
            continue  # Don't recurse into subdirs of a git repo

        for entry in entries:
            if os.path.isdir(entry):
                queue.append(entry)

    return matched_repos

def get_fix_commit_previous_commit_no_compile(container_id, fix_commit, base_dir):
    return run_command_in_container(container_id, wrap_in_cd(f"git rev-parse {fix_commit}^", base_dir))[0].strip()
    

def get_fix_commit_previous_commit(container_id, fix_commit):
    # Step 0: run arvo and get stack trace
    init_vuln_output = run_poc(container_id)
    main_crash_functions_in_stack_trace = find_function_from_major_back_trace(init_vuln_output)['function_and_file_path']

    # Step 1: find a reasonable source file (skip compiler-rt/llvm)
    file_path = ""
    for func_and_file in main_crash_functions_in_stack_trace:
        if "compiler-rt" not in func_and_file[1].lower() and "llvm" not in func_and_file[1].lower():
            file_path = func_and_file[1]
            break
    guessed_basedir = os.path.dirname(file_path)

    # Step 2: determine real git repo root (base_dir)
    container = client.containers.get(container_id)
    result = container.exec_run(f"bash -c 'cd {guessed_basedir} && git rev-parse --show-toplevel'")
    base_dir = result.output.decode().strip()

    # Step 3: checkout to fix commit and test
    result = checkout(container_id, fix_commit, dir=base_dir)
    if result.exit_code != 0:
        print(f"Failed to checkout commit {fix_commit} in container {container_id}.")
        print(f"Searching for the base address of the repo containing {fix_commit}.")
    
        # step 4: find the real git repo root by brute force
        # make a tmp directory storing the src directory in docker

        # First copy the src directory to the host
        with tempfile.TemporaryDirectory() as tmpdirname:
            copy_directory_from_container(container_id, "/src", tmpdirname)
            # Now find the git repo in the tmp directory
            repos = find_repos_with_commit(os.path.join(tmpdirname,"src"), fix_commit)
            if not repos:
                print(f"Cannot find the commit {fix_commit} in any git repo.")
                return None, None, "", 0, "", "", base_dir
            base_dir = repos[0]
            print(f"Found the commit {fix_commit} in repo {base_dir}.")
            relative_path = os.path.relpath(base_dir, tmpdirname)
            base_dir = os.path.join("/", relative_path)
            # checkout to the fix commit
            result = container.exec_run(f"bash -c 'cd {base_dir} && git checkout {fix_commit}'")
            if result.exit_code != 0:
                print(f"Failed to checkout commit {fix_commit} in container {container_id}.")
                return None, None, "", 0, "", "", base_dir
            else:
                print(f"Checked out commit {fix_commit} in container {container_id}.")

    compile_target(container_id)
    output_fix = run_poc(container_id)

    if not check_crash(output_fix):
        # Step 4: find previous commit
        result = container.exec_run(wrap_in_cd(f"git rev-parse {fix_commit}^", base_dir))
        vuln_commit = result.output.decode().strip()

        # Step 5: get diff
        diff_result = container.exec_run(wrap_in_cd(f"git diff {vuln_commit} {fix_commit}", base_dir))
        diff = diff_result.output.decode()

        # Step 6: test vuln commit
        checkout(container_id, vuln_commit, dir=base_dir)
        reset(container_id, base_dir)
        compile_target(container_id)
        output_vuln = run_poc(container_id)

        if_vuln_crash = 1 if check_crash(output_vuln) else 0
    else:
        vuln_commit = None
        diff = ""
        output_vuln = ""
        if_vuln_crash = 0

    return fix_commit, vuln_commit, diff, if_vuln_crash, output_fix, output_vuln, base_dir

def get_base_dir(container_id, tmp_dir, commit = None):
    # Step 0: run arvo and get stack trace
    init_vuln_output = run_poc(container_id)
    main_crash_functions_in_stack_trace = find_function_from_major_back_trace(init_vuln_output)['function_and_file_path']

    # Step 1: find a reasonable source file (skip asan/llvm)
    file_path = ""
    for func_and_file in main_crash_functions_in_stack_trace:
        if "asan" not in func_and_file[1].lower() and "llvm" not in func_and_file[1].lower():
            file_path = func_and_file[1]
            break
    guessed_basedir = os.path.dirname(file_path)

    # Step 2: determine real git repo root (base_dir)
    container = client.containers.get(container_id)
    result = container.exec_run(f"bash -c 'cd {guessed_basedir} && git rev-parse --show-toplevel'")
    base_dir = result.output.decode().strip()
    
    # step 3: checkout whether a given commit is inside the repo if provided
    if commit:
        # get the current commit
        orig_commit = container.exec_run(f"bash -c 'cd {base_dir} && git rev-parse HEAD'").output.decode().strip()
        # note that this may fail if the commit is not in the repo
        result = checkout(container_id, commit, dir=base_dir)
        if result.exit_code == 0:
            # checkout back to the original commit
            res = container.exec_run(f"bash -c 'cd {base_dir} && git checkout {orig_commit}'")
        else:
            # step 4: find the real git repo root by brute force
            # make a tmp directory storing the src directory in docker

            # First copy the src directory to the host
            tmpdirname = os.path.join(tmp_dir, "tmp_src")
            copy_directory_from_container(container_id, "/src", tmpdirname)
            # Now find the git repo in the tmp directory
            repos = find_repos_with_commit(os.path.join(tmpdirname,"src"), commit)
            if not repos:
                return base_dir
            base_dir = repos[0]
            base_dir = os.path.join("/", os.path.relpath(base_dir, tmpdirname))
    return base_dir

def parse_modified_functions_from_diff(container_id,diff_text, git_base_dir):
    """
    Given a unified diff, returns a list of (function_name, file_path) pairs that were actually modified.
    """
    file_changes = {}  # file_path -> set of changed line numbers
    current_file = None

    file_header_regex = re.compile(r'^diff --git a/(.*?) b/')
    hunk_header_regex = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')

    lines = diff_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        file_match = file_header_regex.match(line)
        if file_match:
            current_file = file_match.group(1)
            file_changes[current_file] = set()
            i += 1
            continue

        hunk_match = hunk_header_regex.match(line)
        if hunk_match and current_file:
            new_start = int(hunk_match.group(1))
            new_count = int(hunk_match.group(2)) if hunk_match.group(2) else 1

            new_line_num = new_start
            i += 1
            while i < len(lines) and not lines[i].startswith("diff --git") and not lines[i].startswith("@@"):
                l = lines[i]
                if l.startswith(" "):
                    new_line_num += 1
                elif l.startswith("+"):
                    file_changes[current_file].add(new_line_num)
                    new_line_num += 1
                elif l.startswith("-"):
                    file_changes[current_file].add(new_line_num)
                i += 1
            continue

        i += 1

    result = []
    seen = set()

    for file_path, changed_lines in file_changes.items():
        file_path = os.path.join(git_base_dir, file_path)
        try:
            file_content = get_file_content(container_id, file_path)
            lang =  get_lang_from_filename(file_path)
            if not file_content:
                continue
            functions = get_function_info(file_content, lang)
            if not functions:
                continue
            for func_name, scopes in functions.items():
                for scope in scopes:
                    start_line, end_line = scope
                    if any(start_line <= line <= end_line for line in changed_lines):
                        key = (func_name, file_path)
                        if key not in seen:
                            seen.add(key)
                            result.append(key)
        except Exception as e:
            # print(f"[WARN] Failed to parse modified functions from diff: {e}")
            continue

    return result



def generate_one_data(output_dir, patch_file):
        vuln_data_per_image = {}
        patch_path = os.path.join(args.patch_dir, patch_file)
        meta_path = os.path.join(args.meta_dir, patch_file.replace( ".diff", ".json"))
        container_id = None

        with open(patch_path, "r",encoding="utf-8", errors="ignore") as f:
            patch_content = f.read()
        with open(meta_path, "r", encoding="utf-8", errors="ignore") as f:
            meta = json.load(f)
        try:
            if isinstance(meta["fix_commit"], list):
                raise ValueError("fix_commit is a list")
            fix_commit = meta["fix_commit"]
            local_id = meta["localId"]
            vuln_data_per_image["local_id"] = local_id
            output_json_path = os.path.join(output_dir, f"{local_id}.json")
            if os.path.exists(output_json_path):
                print(f"[INFO] {output_json_path} already exists, skipping.")
                raise ValueError(f"{output_json_path} already exists, skipping.")
            vuln_data_per_image["sanitizer"] = meta["sanitizer"]
            vuln_data_per_image["crash_type"] = meta["crash_type"]
            vuln_data_per_image["project_name"] = meta['project']
            vuln_data_per_image["fix_commit"] = meta['fix_commit']

            # get container_id
            container_id = get_container(meta["localId"])
            # get the vuln_commit and diff
            output_vuln = run_poc(container_id)

            ### Get stack trace
            sanitizer_output = output_vuln.strip()
            vuln_data_per_image["sanitizer_output"]=sanitizer_output
            main_crash_stack_trace_result = find_function_from_major_back_trace(sanitizer_output)     
            main_crash_stack_trace = main_crash_stack_trace_result['stack_trace']
            main_crash_functions_in_stack_trace = main_crash_stack_trace_result['function_and_file_path']

            # Get the overall language
            language = "c"
            for func_and_file_and_line in main_crash_functions_in_stack_trace:
                if "asan" not in func_and_file_and_line[1] and "llvm" not in func_and_file_and_line[1]:
                    if get_lang_from_filename(func_and_file_and_line[1]) == "cpp":
                        language =  "cpp"
                        break
            vuln_data_per_image["language"] = language

            base_dir = get_base_dir(container_id, None)
            if not base_dir:
                print(f"[WARN] Failed to get base dir for container {container_id}")
                raise ValueError(f"[WARN] Failed to get base dir for container {container_id}")
            
            # Attention: In order to get functions before change, We need to first checkout to the commit before the fix commit, and get the right modified line number.
            fix_commit_previous_commit = get_fix_commit_previous_commit_no_compile(container_id, fix_commit,base_dir=base_dir)
            if not fix_commit_previous_commit:
                print(f"[WARN] Failed to get fix commit previous commit for container {container_id}")
                raise ValueError(f"[WARN] Failed to get fix commit previous commit for container {container_id}")

            # Get functions before patch
            function_before_patch=[]
            try:
                vuln_commit_output, exit_code = run_command_in_container(
                    container_id, f"cd {base_dir} && git rev-parse HEAD"
                )
                vuln_commit = vuln_commit_output.strip()
                vuln_data_per_image["vuln_commit"] = vuln_commit
            except Exception as e:
                print(f"[WARN] Failed to get vuln commit: {e}")
                raise e
            
            checkout(container_id, fix_commit_previous_commit, dir=base_dir)
            reset(container_id, base_dir)
            # Get the changed funcs and files in the diff
            changed_func_and_file_and_line_in_patch = parse_modified_functions_from_diff(container_id, patch_content,base_dir)
            changed_func_and_file_and_line_in_patch = [
                (func, os.path.join(base_dir, fpath))
                for func, fpath in changed_func_and_file_and_line_in_patch
            ]
            checkout(container_id, vuln_commit, dir=base_dir)
            reset(container_id, base_dir)

            for func_and_file_and_line in changed_func_and_file_and_line_in_patch:
                language_cur_file = get_lang_from_filename(func_and_file_and_line[1])
                if language_cur_file:
                    try:
                        # Get function body
                        key = f"{func_and_file_and_line[1]}__xx__{func_and_file_and_line[0]}"
                        vul_function_body, start_line, end_line = get_function_content(container_id, key, language)
                        function_before_patch.append({
                            "function_name": func_and_file_and_line[0],
                            "function_body": vul_function_body,
                            "file_path": func_and_file_and_line[1]
                        })
                    except Exception:
                        pass
            
            vuln_data_per_image["function_before_patch"] = function_before_patch
            
            # Get functions after patch
            function_after_patch=[]
            checkout(container_id, fix_commit, dir=base_dir)
            reset(container_id, base_dir)

            for func_and_file_and_line in changed_func_and_file_and_line_in_patch:
                language_cur_file = get_lang_from_filename(func_and_file_and_line[1])
                if language_cur_file:
                    # Get function body
                    try:
                        key = f"{func_and_file_and_line[1]}__xx__{func_and_file_and_line[0]}"
                        vul_function_body, start_line, end_line = get_function_content(container_id, key, language)
                        function_after_patch.append({
                            "function_name": func_and_file_and_line[0],
                            "function_body": vul_function_body,
                            "file_path": func_and_file_and_line[1]
                        })
                    except Exception:
                        pass
            vuln_data_per_image["function_after_patch"] = function_after_patch

            # Filter out the functions in main_crash_functions_in_stack_trace that are alreadly in changed_func_and_file_and_line_in_patch
            # changed_keys = set(
            #     f"{fpath}__xx__{fname}" for fname, fpath in changed_func_and_file_and_line_in_patch
            # )

            # Get functions in stack trace
            functions_in_stack_trace = []
            for func_and_file_and_line in main_crash_functions_in_stack_trace:
                language_cur_file = get_lang_from_filename(func_and_file_and_line[1])
                if language_cur_file:
                    # Get function body
                    key = f"{func_and_file_and_line[1]}__xx__{func_and_file_and_line[0]}"
                    try:
                        vuln_line = ""
                        vul_function_body, start_line, end_line = get_function_content(container_id, key, language, func_and_file_and_line[2])
                        if func_and_file_and_line[2]>= start_line and func_and_file_and_line[2]<=end_line:
                            # Get the line number and the content of the crashing line in the stack trace
                            vuln_line = get_line_from_function(vul_function_body, start_line, end_line, func_and_file_and_line[2])
                        functions_in_stack_trace.append({
                            "function_name": func_and_file_and_line[0],
                            "function_body": vul_function_body,
                            "file_path": func_and_file_and_line[1],
                            "crashing_line": vuln_line,
                            "crashing_line_number": func_and_file_and_line[2]
                        })
                    except Exception:
                        pass
            vuln_data_per_image["functions_in_stack_trace"] = functions_in_stack_trace
            
            # get the functions after fixing
        
            with open(os.path.join(output_dir, f"{local_id}.json"), "w") as f:
                json.dump(vuln_data_per_image, f, indent=4)   
        except Exception as e:
            print(f"[WARN] Failed to process {patch_file}: {e}")
            # If failed, we need to delete the container
        finally:
            if container_id:
                delete_container(container_id)


def main(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    patch_files = [f for f in os.listdir(args.patch_dir) if f.endswith(".diff")]
    patch_files = ['22523.diff']
    if args.num_processes == 1:
        for patch_file in patch_files:
            try:
                generate_one_data(output_dir, patch_file)
            except Exception as e:
                print(f"[WARN] Failed to process one file: {e}")
    else:
        with ProcessPoolExecutor(max_workers=16) as executor:
            futures = [
                executor.submit(generate_one_data, output_dir, patch_file)
                for patch_file in patch_files
            ]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[WARN] Failed to process one file: {e}")


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Convert raw data to our format.")
    parser.add_argument("--patch-dir", type=str, required=True, help="Directory containing patches of arvo.")
    parser.add_argument("--meta-dir", type=str, required=True, help="Directory containing metadata of arvo.")
    parser.add_argument("--output-dir", type=str, default="arvo_raw_data/", help="Directory to save data.")
    parser.add_argument("--num-processes", type=int, default=16, help="Number of processes to use.")
    args = parser.parse_args()
    main(args.output_dir)

    #python generate_data.py --patch-dir [ARVO-Meta dir]/archive_data/patches --meta-dir [ARVO-Meta dir]/archive_data/meta
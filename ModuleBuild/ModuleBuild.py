import os
import re
import shlex
import datetime
import requests

def load_source(url):
    if os.path.isfile(url):
        try:
            with open(url, 'r', encoding='utf-8') as file:
                return file.read()
        except IOError as e:
            print(f"Failed to read local file: {url}: {e}")
            return None
    elif url.startswith("https://"):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Failed to download content from URL: {url}: {e}")
            return None
    else:
        local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), url)
        if os.path.isfile(local_path):
            try:
                with open(local_path, 'r', encoding='utf-8') as file:
                    return file.read()
            except IOError as e:
                print(f"Error reading local file {local_path}: {e}")
                return None
        else:
            print(f"Local file not found: {local_path}")
            return None

def build_sgmodule(rule_text, project_name):
    formatted_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    rule_pattern = r'^(?!.*[#])(.*?)\s*(AND|DOMAIN(?:-KEYWORD|-SUFFIX)?|IP-CIDR|URL-REGEX),'
    rewrite_pattern = r'^(?!.*[#])(.*?)\s*url\s+(reject(?:-200|-array|-dict|-img|-tinygif)?)'
    header_pattern = r'^(?!.*[#])(.*?)\s*url-and-header\s+(reject(?:-drop|-no-drop)?)\s*'
    maplocal_pattern = r'^\s*(?!.*#)(.*?)\s*mock-response-body\s+(.*)$'
    jq_pattern = r'^(?!.*[#])(.*?)\s*response-body-json-jq\s+(?:\'([^\']+)\'|jq-path="([^"]+)")'
    script_pattern = r'^(?!.*[#])(.*?)\s*url\s+(script-(?:response|request)-(?:body|header)|script-echo-response|script-analyze-echo-response)\s+(\S+)'
    body_pattern = r'^(?!.*[#])(.*?)\s*url\s+(response-body)\s+(\S+)\s+(response-body)\s+(\S+)'
    mitm_pattern = r'^\s*hostname\s*=\s*([^\n#]*)\s*(?=#|$)'

    sgmodule_content = f"""#!name={project_name}
#!desc={formatted_time}

[Rule]
"""
    rule_lines = []
    for line in rule_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(rule_pattern, line):
            rule_lines.append(line)
    rule_lines = list(set(rule_lines))
    priority_list = ['AND,', 'DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'URL-REGEX,']
    rule_lines.sort(key=lambda x: (
        next((i for i, p in enumerate(priority_list) if x.startswith(p)), 6),
        (
            lambda ip: [int(o) for o in ip.split('.')] if ':' not in ip else
            [ord(c) - ord('0') if '0' <= c <= '9' else ord(c) - ord('a') + 10 if 'a' <= c <= 'z' else 999
            for c in ip.lower().replace(':', '').ljust(32, '0')]
        )(x.split(',')[1].split('/')[0]) if x.startswith('IP-CIDR,') else [9999]*8,
        x.upper()
    ))
    sgmodule_content += '\n'.join(rule_lines) + '\n'

    sgmodule_content += f"""
[URL Rewrite]
"""
    url_content = ""
    for match in re.finditer(rewrite_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        reject_type = match.group(2).strip()
        url_content += f"{pattern} - {reject_type}\n"
    for match in re.finditer(header_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        reject_type = match.group(2).strip()
        url_content += f"{pattern} url-and-header {reject_type}\n"
    url_lines = [line for line in url_content.splitlines() if line.strip()]
    unique_lines = sorted(set(url_lines))
    url_content = '\n'.join(unique_lines)
    sgmodule_content += url_content + "\n"

    sgmodule_content += f"""
[Map Local]
"""
    map_local_lines = []
    for match in re.finditer(maplocal_pattern, rule_text, re.MULTILINE):
        regex, params_str = match.group(1).strip(), match.group(2).strip()
        lexer = shlex.shlex(params_str, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ''
        kv_pairs = {k: v.replace('"', '\\"') for token in lexer if '=' in token for k, v in [token.split('=', 1)]}
        data_type = kv_pairs.get('data-type', '')
        data = kv_pairs.get('data', '')
        status_code = kv_pairs.get('status-code', '')
        is_base64 = kv_pairs.get('mock-data-is-base64', '').lower() == 'true'
        content_type = 'application/octet-stream' if is_base64 or data_type == 'base64' else {
            'text': 'text/plain',
            'json': 'application/json'
        }.get(data_type, 'application/octet-stream')
        line = f'{regex} data-type={data_type} data="{data}"'
        if status_code:
            line += f' status-code={status_code}'
        line += f' header="Content-Type:{content_type}"'
        map_local_lines.append(line)
    sgmodule_content += '\n'.join(sorted(set(map_local_lines))) + '\n'

    sgmodule_content += f"""
[Body Rewrite]
"""
    http_response_jq = ""
    for match in re.finditer(jq_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        jq_expr = match.group(2)
        jq_path = match.group(3)
        if jq_expr:
            http_response_jq += f"http-response-jq {pattern} '{jq_expr}'\n"
        elif jq_path:
            http_response_jq += f'http-response-jq {pattern} jq-path="{jq_path}"\n'
    sgmodule_content += http_response_jq

    sgmodule_content += f"""
[Script]
"""
    script_content = ""
    for match in re.finditer(script_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        script_type_raw = match.group(2)
        script_path = match.group(3).strip().rstrip(',')
        filename_match = re.search(r'/([^/]+?)(?:\.js)?$', script_path)
        filename = filename_match.group(1).strip() if filename_match else script_path
        script_type = 'response' if script_type_raw in ['script-response-body', 'script-echo-response', 'script-response-header'] else 'request'
        needbody = "true" if script_type_raw in ['script-response-body', 'script-echo-response', 'script-response-header', 'script-request-body', 'script-analyze-echo-response'] else "false"
        params = [f"{filename} =type=http-{script_type}", f"pattern={pattern}", f"script-path={script_path}", f"requires-body={needbody}", "max-size=0"]
        line_start = match.start()
        line_end = rule_text.find('\n', line_start)
        line = rule_text[line_start:line_end if line_end != -1 else None]
        binary_body_mode_match = re.search(r'binary-body-mode\s*=\s*(true|false)', line)
        if binary_body_mode_match:
            params.append(f"binary-body-mode={binary_body_mode_match.group(1)}")
        argument_match = re.search(r'argument\s*=\s*(".*"|{.*}|[.*])', line)
        if argument_match:
            params.append(f'argument={argument_match.group(1)}')
        script_line = ', '.join(params)
        script_content += script_line + "\n"
    script_content = '\n'.join(sorted(set(script_content.splitlines())))
    sgmodule_content += script_content + "\n"
    for match in re.finditer(body_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        re1 = match.group(3).strip()
        re2 = match.group(5).strip()
        sgmodule_content += f"ReplaceBody =type=http-response, pattern={pattern}, script-path=https://xiangwanguan.github.io/Shadowrocket/Rewrite/JavaScript/ReplaceBody.js, requires-body=true, argument={re1}->{re2},max-size=0\n"
    mitm_matches = set()
    for match in re.finditer(mitm_pattern, rule_text, re.MULTILINE):
        hostnames = match.group(1).split(',')
        mitm_matches.update(host.strip() for host in hostnames if host.strip())
    mitm_match_content = ','.join(sorted(mitm_matches))

    sgmodule_content += f"""
[MITM]
hostname = %APPEND% {mitm_match_content}
"""
    return sgmodule_content

def generate_sgmodule(rule_sources, project_name, parent_dir):
    merged_rule_text = ""
    for url in rule_sources:
        rule_text = load_source(url)
        if rule_text:
            merged_rule_text += rule_text + "\n"
        else:
            print(f"Unable to retrieve or process rule source: {url}")
    sgmodule_content = build_sgmodule(merged_rule_text, project_name)
    if sgmodule_content:
        output_file = os.path.join(parent_dir, "Module.sgmodule")
        save_sgmodule(sgmodule_content, output_file)
        print(sgmodule_content)
        print(f"Module successfully generated and saved to: {output_file}")
    else:
        print("No valid content found — module generation skipped.")

def save_sgmodule(content, file_path):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except IOError as e:
        print(f"Failed to save output file: {file_path}: {e}")

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    input_file_path = os.path.join(parent_dir, "ModuleBuild", "BuildList.conf")
    print("Input file path:", input_file_path)
    try:
        with open(input_file_path, 'r') as file:
            build_entries = [line.strip() for line in file if line.strip() and not line.strip().startswith('#')]
    except IOError as e:
        print(f"Failed to read input file: {e}")
        exit(1)
    generate_sgmodule(build_entries, "融合模块", parent_dir)

if __name__ == "__main__":
    main()

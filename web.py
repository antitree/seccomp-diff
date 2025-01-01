from common.diff import compare_seccomp_policies, get_seccomp_policy
from common import containerd
from common import docker
from flask import Flask, render_template, render_template_string, request, jsonify, send_from_directory, abort

import json
import markdown
import os
import re

app = Flask(__name__,
            static_folder="web/static",
            template_folder="web/templates",
            )
if app.debug: 
    app.config["PROPAGATE_EXCEPTIONS"] = True
app.config["MODE"] = "k8s"

@app.route('/')
def index():
    """Render the home page."""
    return render_template('index.html')


def list_docker():
    container_pids = docker.get_containers()
    containers = []
    for container, values in container_pids.items():
        containers.append(values)
    
    return {"containers": containers}
    

def list_k8s(namespace="k8s.io"):
    container_pids = containerd.get_containers(namespace=namespace)
    containers = []
    # TODO there's a better way to do this but I'm tired
    for container, values in container_pids.items():
        containers.append(values)
    return {"containers": containers}
    

@app.route('/list_containers', methods=['POST'])
def list_containers():
    """Return a list of running containers."""
    
    try:
        if app.config["MODE"] == "Docker": 
            # TODO testing if I need docker at all
            #return jsonify(list_docker())
            return jsonify(list_docker())
        else:
            return jsonify(list_k8s(namespace="k8s.io"))
    except Exception as e:
        app.logger.error(f"Error during listing containers: {e} ")
        return jsonify({"error": str(e)}), 500

def table_to_json(table, full1=None, full2=None):
    """
    Converts a rich Table object into a JSON-serializable dictionary.
    """
    headers = [column.header for column in table.columns]
    rows = [[cell.text for cell in row] for row in table._custom_rows]
    #app.logger.debug(f"Headers: {headers}")
    #app.logger.debug(f"Rows: {rows}")
    # app.logger.error(full1)
    return json.dumps({"headers": headers, "rows": rows, "full": [full1, full2]})

@app.route('/syscalls/<filename>.html')
def render_markdown_as_html(filename):
    """Render specific sections of a Markdown file as HTML."""
    filepath = os.path.join(app.static_folder, 'syscalls', f"{filename}.md")
    
    if not os.path.exists(filepath):
        abort(404, description=f"Markdown file {filename}.md not found.")

    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()

    # Extract specific sections
    sections_to_include = ["Description", "Example Use Case", "Issues"]
    extracted_sections = []
    
    for section in sections_to_include:
        pattern = rf"^## {section}\n(.*?)(?=\n##|\Z)"  # Regex to match the section content
        match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
        if match:
            extracted_sections.append(f"## {section}\n{match.group(1).strip()}")

    # Combine and convert to HTML
    filtered_content = "\n\n".join(extracted_sections)
    html_content = markdown.markdown(filtered_content)

    # Render as HTML
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{filename.capitalize()} Syscall</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-dark text-light p-4">
        <div class="container">
            <h1 class="text-center">{filename.capitalize()} Syscall</h1>
            <div class="content mt-4">
                {html_content}
                
                <p>All content from the excellent folks at Aquasecurity. See <a href="https://github.com/aquasecurity/tracee/blob/main/docs/docs/events/builtin/syscalls/">Syscall Documentation</a> used in this page.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template)
    

@app.route('/js/<path:path>', methods=['GET'])
def get_js(path):
     return send_from_directory(os.path.join(app.static_folder, 'js'), path)
 
@app.route('/css/<path:path>', methods=['GET'])
def get_css(path):
     return send_from_directory(os.path.join(app.static_folder, 'css'), path)
 
@app.route('/fonts/<path:path>', methods=['GET'])
def get_font(path):
     return send_from_directory(os.path.join(app.static_folder, 'fonts'), path)
 
@app.route('/debug', methods=['GET'])
def run_debug():
    if app.debug: 
        return jsonify(str(containerd.get_containers(namespace="k8s.io")))
    else:
        return jsonfiy("")
     
@app.route('/update-config', methods=['POST'])
def update_config():
    data = request.json
    if 'mode' in data:
        app.config["MODE"] = data['mode']
        app.logger.warning(data["mode"])
    if 'debug' in data:
        app.config["DEBUG"] = data['debug']
    return jsonify({"status": "success"})

@app.route('/run_seccomp_diff', methods=['POST'])
def run_seccomp_diff():
    """Run the seccomp_diff function with selected container details."""
    container_selection = request.json.get('containers')
    if not container_selection or len(container_selection) != 2:
        return jsonify({"error": "Please select exactly two containers."}), 400

    try:
        container1, container2 = container_selection
        # app.logger.debug(f'Container1: {container1}')
        # app.logger.debug(f'Container2: {container2}')

        

        # Generate the table using compare_seccomp_policies
        table,full1,full2 = compare_seccomp_policies(container1, container2)
        #app.logger.warning(full1)
        
        # Convert the table to JSON
        table_json = table_to_json(table, full1, full2)
        return jsonify({"output": table_json})
    except ValueError as e:
        return jsonify({"diff error": str(e)}), 500
    
@app.route('/get_container', methods=['POST'])
def get_container():
    """Fetch details for a single container."""
    container = request.json.get('container')
    if not container:
        return jsonify({"error": "Please select a container."}), 400

    try:
        container = get_seccomp_policy(container)

        return jsonify({"details": container_details})
    except Exception as e:
        app.logger.error(f"Error fetching container details: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

from datetime import datetime
from flask import Flask, jsonify, render_template_string, request, send_from_directory
from gzip import GzipFile
from io import BytesIO
from uuid import uuid4
from pathlib import Path
import base64
import pdfplumber

UPLOADS = Path('./reports')
UPLOADS.mkdir(exist_ok=True, parents=True)

app = Flask(__name__)


@app.route('/')
def index():
    folders = {}
    for folder in UPLOADS.glob('*'):
        print(folder)
        if not folder.is_file():
            files = [file.relative_to(folder) for file in folder.glob('*')]
            folders[folder.relative_to(UPLOADS)] = files

    return render_template_string('''
        <h1>Reports</h1>
        <ul>
            {% for folder, files in folders.items() %}
                <li>{{ folder }}
                    <ul>
                        {% for file in files %}
                            <li><a href="/download/{{ folder }}/{{ file }}">{{ file }}</a></li>
                        {% endfor %}
                    </ul>
                </li>
            {% endfor %}
        </ul>
    ''', folders=folders)


@app.route('/data', methods=['POST'])
def decode_data():
    data_base64 = request.form.get('data')
    if not data_base64:
        return jsonify({'data': 'Error, no data recieved'})

    data_base64 += '=' * (-len(data_base64) % 4)  # Adjust padding
    data_compressed = base64.b64decode(data_base64)
    with GzipFile(fileobj=BytesIO(data_compressed)) as f:
        data_decompressed = f.read()

    folder = get_upload_folder()
    with open(get_upload_filename(folder, 'pdf'), 'wb') as out:
        out.write(data_decompressed)

    text = pdf_to_text(data_decompressed)
    with open(get_upload_filename(folder, 'txt'), 'w') as out:
        out.write(text)

    return jsonify({'data': text})


@app.route('/download/<folder>/<filename>')
def download(folder, filename):
    return send_from_directory(UPLOADS / folder, filename)


def pdf_to_text(pdf_content):
    with pdfplumber.open(BytesIO(pdf_content)) as pdf:
        text = ''.join(
            page.extract_text() + "\n"
            for page in pdf.pages
        )
    return text


def get_upload_folder():
    name = str(datetime.now()).split('.')[0].replace(' ', 'T')
    path = UPLOADS / name
    path.mkdir(exist_ok=True, parents=True)
    return path


def get_upload_filename(folder: Path, extension: str):
    name = f'{uuid4()}.{extension}'
    path = (folder / name).absolute()
    return path


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8002)

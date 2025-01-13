from flask import Flask, render_template, request, jsonify, Response
import requests
import os
import hashlib
import time
from celery import Celery
import json

app = Flask(__name__)

# Konfigurasi VirusTotal API
VT_API_BASE_URL = "https://www.virustotal.com/api/v3"

# Konfigurasi Celery (sesuaikan dengan pengaturan broker Anda)
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

@celery.task
def scan_url_task(url, vt_api_key):
    """Tugas Celery untuk memindai URL menggunakan VirusTotal API."""
    vt_api_url = f"{VT_API_BASE_URL}/urls"
    headers = {
        "x-apikey": vt_api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = f"url={url}"

    try:
        # Kirim permintaan POST untuk mengirimkan URL untuk dipindai
        response = requests.post(vt_api_url, headers=headers, data=data)
        response.raise_for_status()

        analysis_id = response.json()['data']['id']

        # Periksa status pemindaian hingga selesai
        while True:
            report_url = f"{VT_API_BASE_URL}/analyses/{analysis_id}"
            response = requests.get(report_url, headers=headers)
            response.raise_for_status()

            report = response.json()
            status = report['data']['attributes']['status']
            
            if status == "completed":
                return report

            time.sleep(5)  # Tunggu 5 detik sebelum memeriksa lagi

    except requests.exceptions.RequestException as e:
        return {"error": f"Gagal: {url} - Error: {e}"}

@app.route("/scan_url", methods=["POST"])
def scan_url():
    url_to_scan = request.form.get("url")
    vt_api_key = request.form.get("api_key")

    if not url_to_scan:
        return jsonify({"error": "URL tidak boleh kosong"}), 400
    if not vt_api_key:
        return jsonify({"error": "Kunci API VirusTotal diperlukan"}), 400

    # Jalankan tugas Celery secara asinkron
    task = scan_url_task.delay(url_to_scan, vt_api_key)

    # Kembalikan ID tugas dan instruksi untuk menggunakan SSE
    return jsonify({"task_id": task.id}), 200

@app.route("/scan_file", methods=["POST"])
def scan_file():
    uploaded_file = request.files.get("file")
    vt_api_key = request.form.get("api_key")

    if not uploaded_file:
        return jsonify({"error": "File tidak boleh kosong"}), 400
    if not vt_api_key:
        return jsonify({"error": "Kunci API VirusTotal diperlukan"}), 400

    file_path = secure_save_file(uploaded_file)

    # Kirim kunci API bersama dengan file
    scan_result = scan_file_with_api(file_path, vt_api_key)

    os.remove(file_path)
    return jsonify(scan_result)

@app.route("/get_result/<task_id>")
def get_result(task_id):
    vt_api_key = request.args.get("api_key")
    if not vt_api_key:
        return jsonify({"error": "Kunci API VirusTotal diperlukan"}), 400

    task = scan_url_task.AsyncResult(task_id)
    if task.state == "PENDING":
        response = {
            "state": task.state,
            "status": "Pemindaian sedang berlangsung..."
        }
    elif task.state != "FAILURE":
        response = {
            "state": task.state,
            "result": task.result
        }
    else:
        response = {
            "state": task.state,
            "error": str(task.info)
        }
    return jsonify(response)

@app.route("/")
def index():
    return render_template("index.html")

def scan_file_with_api(file_path, vt_api_key):
    """Mengirimkan file ke API pemindaian virus dan mengembalikan hasilnya."""
    # Contoh menggunakan VirusTotal API

    # 1. Hitung hash file
    file_hash = calculate_file_hash(file_path)

    # 2. Periksa apakah file sudah ada di database VirusTotal
    if check_file_in_virustotal(file_hash, vt_api_key):
        # 3. Jika ada, ambil laporan
        scan_result = get_virustotal_report(file_hash, vt_api_key)
    else:
        # 4. Jika tidak, unggah file untuk dipindai
        scan_result = upload_file_to_virustotal(file_path, vt_api_key)

    return scan_result

def calculate_file_hash(file_path):
    """Menghitung hash SHA-256 dari sebuah file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def check_file_in_virustotal(file_hash, vt_api_key):
    """Memeriksa apakah file dengan hash yang diberikan ada di database VirusTotal."""
    headers = {
        "x-apikey": vt_api_key
    }
    url = f"{VT_API_BASE_URL}/files/{file_hash}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"Error checking file in VirusTotal: {e}")
        return False

def get_virustotal_report(file_hash, vt_api_key):
    """Mengambil laporan VirusTotal untuk hash file yang diberikan."""
    headers = {
        "x-apikey": vt_api_key
    }
    url = f"{VT_API_BASE_URL}/files/{file_hash}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error getting VirusTotal report: {e}")
        return {"error": "Gagal mengambil laporan VirusTotal", "details": str(e)}

def upload_file_to_virustotal(file_path, vt_api_key):
    """Mengunggah file ke VirusTotal untuk dipindai."""
    headers = {
        "x-apikey": vt_api_key
    }
    url = f"{VT_API_BASE_URL}/files"
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file)}
        try:
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
            # Ambil ID analisis dari respons
            analysis_id = response.json().get('data', {}).get('id')
            if analysis_id:
                # Dapatkan laporan analisis
                report_url = f"{VT_API_BASE_URL}/analyses/{analysis_id}"
                while True:
                    report_response = requests.get(report_url, headers=headers)
                    report_response.raise_for_status()
                    report = report_response.json()
                    status = report.get('data', {}).get('attributes', {}).get('status')
                    if status == "completed":
                        return report
                    time.sleep(5)  # Tunggu 5 detik sebelum memeriksa lagi
            else:
                return {"error": "Tidak ada ID analisis yang ditemukan dalam respons", "details": response.text}
        except requests.exceptions.RequestException as e:
            print(f"Error uploading file to VirusTotal: {e}")
            return {"error": "Gagal mengunggah file ke VirusTotal", "details": str(e)}

def secure_save_file(file):
    filename = file.filename
    if not filename:
        raise ValueError("Nama file tidak valid")

    filename = "".join(c for c in filename if c.isalnum() or c in "._-")
    filepath = os.path.join(app.root_path, "uploads", filename)

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    file.save(filepath)
    return filepath

if __name__ == "__main__":
    app.run(debug=True)

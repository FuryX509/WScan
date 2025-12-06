from flask import Flask, request, jsonify
import subprocess
import mysql.connector

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'mantis'
}

app = Flask(__name__)

def connect_db():
    return mysql.connector.connect(**DB_CONFIG)

def insertROW(url, token):
    conn = connect_db()
    cursor = conn.cursor()
    query = "INSERT INTO watchdog (url, token) VALUES (%s, %s);"
    cursor.execute(query, (url, token))
    conn.commit()
    cursor.close()
    conn.close()

def run_script(u,t):
    subprocess.Popen(['py', 'bcrawler.py', '-d', u, '-t', t])

@app.route('/api/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    url = data.get('address')
    token = data.get('token')

    insertROW(url, token)
    #run_script(url, token)

    return jsonify({'message': f'Data received for {url} with token {token}'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8282, debug=True)


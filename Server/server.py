import flask
from flask import request, jsonify
from PKE import PKE
import subprocess

import uuid

app = flask.Flask(__name__)
app.config["DEBUG"] = True
node_Agreements = []

@app.route('/api/authorisation/publickey', methods=['POST'])
def api_compute_secret():
  node_id = request.values['node_id']
  public_key = request.values['public_key']
  'Compute shared secret from server_pke.private_key and public_key'
  agreement = {
    'node_id': node_id,
    'node_public_key': public_key,
    'node_secret': 'NODE SECRET'
  }
  node_Agreements.append(agreement)
  return_object = {
    'server_id': server_pke.uuid,
    'public_key': server_pke.public_key
  }
  return jsonify(return_object)

if __name__ == "__main__":
  server_pke = PKE()
  app.run()